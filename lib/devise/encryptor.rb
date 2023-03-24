# frozen_string_literal: true

require 'bcrypt'

module Devise
  module Encryptor
    def self.digest(klass, password)
      if klass.pepper.present?
        password = "#{password}#{klass.pepper}"
      end
      BCryptEncryptor.create_password(password, cost: klass.stretches)
    end

    def self.compare(klass, hashed_password, password)
      return false if hashed_password.blank?

      password = BCryptEncryptor.compare_password("#{password}#{klass.pepper}", hashed_password)
      Devise.secure_compare(password, hashed_password)
    end
  end
end
