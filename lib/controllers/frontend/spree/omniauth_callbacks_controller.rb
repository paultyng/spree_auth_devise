module Spree
  class OmniauthCallbacksController < Devise::OmniauthCallbacksController
    def standard_provider
      hash = request.env["omniauth.auth"]
      provider = hash.provider

      @user = User.from_omniauth(hash)

      if @user.previous_changes.key?('created_at') #new record that was saved?
        sign_in @user
        session["devise.omniauth_data"] = hash
        set_flash_message(:notice, :signed_up)
        redirect_to after_sign_up_path_for(@user)
      else
        set_flash_message(:notice, :signed_in) if is_navigational_format?
        sign_in_and_redirect @user, :event => :authentication #this will throw if @user is not activated
      end
    end

    alias_method :facebook, :standard_provider
    alias_method :google_oauth2, :standard_provider
    alias_method :developer, :standard_provider if Rails.env.development?

    def after_sign_up_path_for(resource)
      after_sign_in_path_for(resource)
    end
  end
end
