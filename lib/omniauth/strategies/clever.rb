require 'omniauth-oauth2'
require 'base64'

module OmniAuth
  module Strategies
    class Clever < OmniAuth::Strategies::OAuth2
      option :name, "clever"

      option :client_options, {
        :site          => 'https://api.clever.com',
        :authorize_url => 'https://clever.com/oauth/authorize',
        :token_url     => 'https://clever.com/oauth/tokens'
      }

      def authorize_params
        super.tap do |params|
          params[:scope] = 'read:students,read:teachers,read:user_id'
          params[:clever_landing] = options.client_options.clever_landing || 'admin'
          if options.client_options.dev
            params[:dev] = options.client_options.dev
          end
          params[:response_type] = 'code'
          params[:approval_prompt] = 'auto'
          params[:state] = SecureRandom.hex(24)
        end
      end

      def token_params
        username_password = options.client_id + ":" + options.client_secret
        base64_username_password = Base64.encode64(username_password).gsub("\n","")
        super.tap do |params|
          params[:headers] = {'Authorization' => "Basic #{base64_username_password}"}
        end
      end



      uid{ raw_info['data']['id'] }

      info do
        { :user_type => raw_info['type'] }.merge(raw_info['data']).merge(raw_user_info['data'])
      end

      extra do
        {
          'raw_info' => raw_info,
          'raw_user_info' => raw_user_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('/me').parsed
      end

      def raw_user_info
        return @raw_user_info if @raw_user_info
        
        user_type = raw_info['type']
        user_id = raw_info['data']['id']
        if user_type && user_id
          @raw_user_info = access_token.get("/v1.1/#{user_type}s/#{user_id}").parsed
        else
          @raw_user_info = {}
        end

        @raw_user_info
      end
    end
  end
end