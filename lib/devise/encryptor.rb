# frozen_string_literal: true

require 'bcrypt'

module Devise
  module Encryptor 
    extend self
    def digest(klass, password)
      Rails.logger.info('ARGON2 Password Creation')
      hasher = Argon2::Password.new(m_cost:, p_cost:, secret:, t_cost:)
      hasher.create(password)
    end

    def compare(klass, hashed_password, password)
      Rails.logger.info('ARGON2 Password Verification')
      Argon2::Password.verify_password(
        "#{password}#{klass.pepper}",
        hashed_password,
        secret
      )
    end

    private

    def m_cost
      @__m_cost__ ||= Rails.application.secrets.argon2_m_cost || 20
    end

    def p_cost
      @__p_cost__ ||= 1
    end

    def secret
      @__secret__ ||= Rails.application.secrets.argon2_secret || '4gcnu3X1Kmuz5p8woCeeRSVr6NJFHAwFoEHqfQWeRA8' 
    end

    def t_cost
      @__t_cost__ ||= 2
    end
  end
end
