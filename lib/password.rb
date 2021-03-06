# -*- ruby encoding: utf-8 -*-
require 'digest/sha1'
require 'digest/md5'
require 'base64'

class Net::LDAP::Password
  class << self
    # Generate a password-hash suitable for inclusion in an LDAP attribute.
    # Pass a hash type as a symbol (:md5, :sha, :ssha) and a plaintext
    # password. This function will return a hashed representation.
    #
    #--
    # STUB: This is here to fulfill the requirements of an RFC, which
    # one?
    #
    # TODO:
    # * maybe salted-md5
    # * Should we provide sha1 as a synonym for sha1? I vote no because then
    #   should you also provide ssha1 for symmetry?
    #
    attribute_value = ""
    def generate(type, str)
       case type
         when :md5
            attribute_value = '{MD5}' + Base64.encode64(Digest::MD5.digest(str)).chomp! 
         when :sha
            attribute_value = '{SHA}' + Base64.encode64(Digest::SHA1.digest(str)).chomp! 
         when :ssha
            srand; salt = (rand * 1000).to_i.to_s 
            attribute_value = '{SSHA}' + Base64.encode64(Digest::SHA1.digest(str + salt) + salt).chomp!
         else
            raise Net::LDAP::LdapError, "Unsupported password-hash type (#{type})"
         end
      return attribute_value
    end

    # Password validation
    def validate(password, username)

      # Disallowed patterns in passwords
      invalid_patterns = [
        "qwerty",
        "asdf",
        "1234",
      ]
      password_is_valid = false

      # Regexes to check for password complexity.
      #
      # In order:
      # - Verify we have at least two special characters
      # - Verify that our password isn't a palindrome
      # - Verify that none of our disallowed patterns are present
      # - Verify that the password does not contain 3-character sequences contained in the username
      # - Verify that the password is between 12 and 99 characters long
      # - Verify that the password contains a lowercase letter
      # - Verify that the password contains an uppercase letter
      # - Verify that the password contains a number

      if not password =~ /[\~\!\@\#\$\%\^\&\*\(\)\`\-\_\+\=\{\}\[\]\|\\\;\:\'\"\<\>\,\.\/\?]/
        error_message = "Passwords must have at least 1 special character."
      elsif password == password.reverse
        error_message = "Passwords cannot be palindromes."
      elsif password =~ /#{invalid_patterns.join("|")}/
        error_message = "Passwords may not contain #{invalid_patterns.join(", ")}."
      elsif "#{username}\n#{password}" =~ /(?=(...)[^\n]*\n(?:(?!\1).)*\1)/
        error_message = "Passwords may not contain more than 3 characters in common with your user ID."
      elsif not password =~ /^.{12,99}$/
        error_message = "Passwords must be between 12 and 99 characters long."
      elsif not password =~ /[a-z]/
        error_message = "Passwords must contain at least 1 lowercase letter."
      elsif not password =~ /[A-Z]/
        error_message = "Passwords must contain at least 1 uppercase letter."
      elsif not password =~ /[0-9]/
        error_message = "Passwords must contain at least 1 number."
      else
        character_count     = password.scan(/\w/).inject(Hash.new(0)){|hash, character| hash[character] += 1; hash}
        repeated_characters = false

        character_count.each do |key, value|
          if value > 2
            repeated_characters = true
            error_message       = "Passwords cannot contain the same character more than twice."
          end
        end

        if repeated_characters == false
          password_is_valid = true
          error_message     = ''
        end
      end

      return_hash = {
        :password_is_valid => password_is_valid,
        :error_message     => error_message,
      }
    end
  end
end
