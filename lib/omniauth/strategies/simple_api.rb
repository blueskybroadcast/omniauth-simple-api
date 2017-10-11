require 'omniauth-oauth2'
require 'builder'

module OmniAuth
  module Strategies
    class SimpleApi < OmniAuth::Strategies::OAuth2

      option :client_options, {
        site: 'https://api.simple-api.com:443',
        authorize_url: '/auth/vendor',
        user_info_url: '/customers',
        auth_token: 'MUST BE SET'
      }

      option :name, 'simple_api'

      uid { raw_info['customerId'] }

      info do
        {
          first_name: raw_info['firstName'],
          last_name: raw_info['lastName'],
          email: raw_info['primaryEmail'],
          roles: raw_member_roles
        }
      end

      extra do
        { raw_info: raw_info }
      end

      def creds
        self.access_token
      end

      def request_phase
        slug = session['omniauth.params']['origin'].gsub(/\//, '')
        account = Account.find_by(slug: slug)
        @app_event = account.app_events.create(activity_type: 'sso')

        auth_request = authorize(callback_url, slug)

        unless auth_request
          @app_event.logs.create(level: 'error', text: 'Invalid credentials')
          return fail!(:invalid_credentials)
        end

        redirect auth_request['data']['authUrl']
      end

      def callback_phase
        slug = request.params['slug']
        account = Account.find_by(slug: slug)
        @app_event = account.app_events.where(id: request.params['event']).first_or_create(activity_type: 'sso')

        if customer_token

          self.access_token = {
            token: customer_token
          }

          self.env['omniauth.auth'] = auth_hash
          self.env['omniauth.origin'] = '/' + slug
          self.env['omniauth.app_event_id'] = @app_event.id
          finalize_app_event
          call_app!
        else
          @app_event.logs.create(level: 'error', text: 'Invalid credentials')
          @app_event.fail!
          fail!(:invalid_credentials)
        end
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash.credentials = creds
        hash
      end

      def raw_info
        @raw_info ||= get_user_info(customer_token)
      end

      def raw_member_roles
        @raw_member_roles ||= get_member_roles
      end

      def customer_id
        raw_info['customerId']
      end

      private

      def auth_token
        options.client_options.auth_token
      end

      def auth_url
        "#{options.client_options.site}#{options.client_options.authorize_url}"
      end

      def authorize(callback, slug)
        callback_url = "#{callback}?slug=#{slug}&event=#{@app_event.id}"

        request_log = "SimpleAPI Authentication Request:\nGET #{auth_url}?return=#{callback_url}"
        @app_event.logs.create(level: 'info', text: request_log)

        response = Typhoeus.get(auth_url + "?return=#{callback_url}",
          headers: { Authorization: "Basic #{auth_token}" }
        )
        log_request_details(__callee__, response)

        if response.success?
          JSON.parse(response.body)
        else
          @app_event.fail!
          nil
        end
      end

      def customer_token
        request.params['ct']
      end

      def get_member_roles
        request_log = "SimpleAPI Authentication Request:\nGET #{member_roles_url}"
        @app_event.logs.create(level: 'info', text: request_log)

        response = Typhoeus.get(member_roles_url,
          headers: { Authorization: "Basic #{auth_token}" }
        )
        log_request_details(__callee__, response)

        if response.success?
          JSON.parse(response.body)['data']['roles']
        else
          nil
        end
      end

      def get_user_info(customer_token)
        request_log = "SimpleAPI Authentication Request:\nGET #{user_info_url}?token=#{Provider::SECURITY_MASK}"
        @app_event.logs.create(level: 'info', text: request_log)

        response = Typhoeus.get(user_info_url + "?token=#{customer_token}",
          headers: { Authorization: "Basic #{auth_token}" })
        log_request_details(__callee__, response)

        if response.success?
          JSON.parse(response.body)['data']['customers'].first
        else
          nil
        end
      end

      def log_request_details(callee, response)
        Rails.logger.info "%% #{options.name} #{callee.to_s}:: "\
          "date: #{response.headers['date']}; "\
          "server: #{response.headers['server']}; "\
          "request-id: #{response.headers['request-id']}; "\
          "response-time: #{response.headers['response-time']}; %%"

        response_log = "SimpleAPI Authentication Response (code: #{response&.code}):\n#{response.inspect}"
        log_level = response.success? ? 'info' : 'error'
        @app_event.logs.create(level: log_level, text: response_log)
      end

      def member_roles_url
        "#{user_info_url}/#{customer_id}/roles"
      end

      def user_info_url
        "#{options.client_options.site}#{options.client_options.user_info_url}"
      end

      def finalize_app_event
        app_event_data = {
          user_info: {
            uid: raw_info['customerId'],
            first_name: info[:first_name],
            last_name: info[:last_name],
            email: info[:email]
          }
        }

        @app_event.update(raw_data: app_event_data)
      end
    end
  end
end
