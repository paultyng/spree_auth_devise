module Spree
  class User < ActiveRecord::Base
    include Core::UserAddress
    include Core::UserPaymentSource

    devise :omniauthable, :database_authenticatable, :registerable, :recoverable,
           :rememberable, :trackable, :validatable, :encryptable,
           :encryptor => 'authlogic_sha512',
           omniauth_providers: [:facebook, :google_oauth2] + (Rails.env.development? ? [:developer] : [])

    has_many :orders

    before_validation :set_login
    before_destroy :check_completed_orders

    users_table_name = User.table_name
    roles_table_name = Role.table_name

    scope :admin, -> { includes(:spree_roles).where("#{roles_table_name}.name" => "admin") }

    class DestroyWithOrdersError < StandardError; end

    def self.admin_created?
      User.admin.count > 0
    end

    def admin?
      has_spree_role?('admin')
    end

    def self.from_omniauth(auth)
      raise 'An email is required to use an external provider.' if auth.try(:info).try(:email).blank?

      where(email: auth.info.email).first_or_create do |user|
        user.email = auth.info.email
      end
    end

    protected
      def password_required?
        !persisted? || password.present? || password_confirmation.present?
      end

    private

      def check_completed_orders
        raise DestroyWithOrdersError if orders.complete.present?
      end

      def set_login
        # for now force login to be same as email, eventually we will make this configurable, etc.
        self.login ||= self.email if self.email
      end
  end
end
