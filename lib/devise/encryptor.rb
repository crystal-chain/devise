# frozen_string_literal: true

require 'bcrypt'

module Devise
  module Encryptor 
    extend self
    def digest(klass, password)
      Rails.logger.info("ARGON2 Password Creation m_cost: #{m_cost}, p_cost: #{p_cost}, t_cost: #{t_cost}")
      hasher = Argon2::Password.new(m_cost:, p_cost:, secret:, t_cost:)
      hasher.create(password)
    end

    def compare(klass, hashed_password, password)
      Rails.logger.info('ARGON2 Password Verification')
      require "pry"; binding.pry
      Argon2::Password.verify_password(
        "#{password}#{klass.pepper}",
        hashed_password,
        secret
      )
    end

    private

    def m_cost
      @__m_cost__ ||= Devise.argon2_m_cost
    end

    def p_cost
      @__p_cost__ ||= 1
    end

    def secret
      @__secret__ ||= Devise.secret_key
    end

    def t_cost
      @__t_cost__ ||= 2
    end
  end
end
