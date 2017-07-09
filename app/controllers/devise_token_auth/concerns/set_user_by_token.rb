module DeviseTokenAuth::Concerns::SetUserByToken
  extend ActiveSupport::Concern
  include DeviseTokenAuth::Controllers::Helpers

  included do
    before_action :set_request_start
    after_action :update_auth_header
  end

  protected

  # keep track of request duration
  def set_request_start
    @request_started_at = Time.now
    @used_auth_by_token = true
  end

  # user auth
  def set_user_by_token(mapping=nil)
    # determine target authentication class
    print 'mapping: ', mapping
    rc = resource_class(mapping)

    # no default user defined
    return unless rc

    #gets the headers names, which was set in the initialize file
    uid_name = DeviseTokenAuth.headers_names[:'uid']
    access_token_name = DeviseTokenAuth.headers_names[:'access-token']
    client_name = DeviseTokenAuth.headers_names[:'client']

    # parse header for values necessary for authentication
    uid        = request.headers[uid_name] || params[uid_name]
    @token     ||= request.headers[access_token_name] || params[access_token_name]
    @client_id ||= request.headers[client_name] || params[client_name]
    p uid, @token, @client_id, params[uid_name], params, uid_name

    # client_id isn't required, set to 'default' if absent
    @client_id ||= 'default'

    # check for an existing user, authenticated via warden/devise, if enabled
    if DeviseTokenAuth.enable_standard_devise_support
      p 'DeviseTokenAuth.enable_standard_devise_support'
      devise_warden_user = warden.user(rc.to_s.underscore.to_sym)
      if devise_warden_user && devise_warden_user.tokens[@client_id].nil?
        @used_auth_by_token = false
        @resource = devise_warden_user
        @resource.create_new_auth_token
      end
    end

    p '@resource: ', @resource
    # user has already been found and authenticated
    return @resource if @resource && @resource.class == rc

    p '!@resource || @resource.class != rc'
    # ensure we clear the client_id

    if !@token
      p '@token is nil'
      @client_id = nil
      return
    end

    p '@token is not nil'

    return false unless @token
    p '!@token'

    # mitigate timing attacks by finding by uid instead of auth token
    if rc.respond_to?(:find_by_uid) then
      user = uid && rc.find_by_uid(uid)
    else
      user = uid && rc.where(:uid => uid).last
    end
    p 'user', user

    if user && user.valid_token?(@token, @client_id)
      # sign_in with bypass: true will be deprecated in the next version of Devise
      if self.respond_to? :bypass_sign_in
        bypass_sign_in(user, scope: :user)
      else
        sign_in(:user, user, store: false, bypass: true)
      end
      return @resource = user
    else
      # zero all values previously set values
      p 'user is null'
      @client_id = nil
      return @resource = nil
    end
  end


  def update_auth_header
    print 'set_user_by_token update_auth_header @resource: ', @resource, ' client_id: ', @client_id
    print '@resource.valid?: ', @resource.valid? if @resource
    # cannot save object if model has invalid params
    return unless @resource && @resource.valid? && @client_id

    print '@used_auth_by_token: ', @used_auth_by_token
    # Generate new client_id with existing authentication
    @client_id = nil unless @used_auth_by_token

    print 'DeviseTokenAuth.change_headers_on_each_request: ', DeviseTokenAuth.change_headers_on_each_request
    if @used_auth_by_token && !DeviseTokenAuth.change_headers_on_each_request
      print 'inside 1'
      # should not append auth header if @resource related token was
      # cleared by sign out in the meantime
      return if @resource.reload.tokens[@client_id].nil?

      auth_header = @resource.build_auth_header(@token, @client_id)

      # update the response header
      response.headers.merge!(auth_header)

    else

      # Lock the user record during any auth_header updates to ensure
      # we don't have write contention from multiple threads
      @resource.with_lock do
        print 'inside lock'
        # should not append auth header if @resource related token was
        # cleared by sign out in the meantime
        return if @used_auth_by_token && @resource.tokens[@client_id].nil?

        # determine batch request status after request processing, in case
        # another processes has updated it during that processing
        @is_batch_request = is_batch_request?(@resource, @client_id)

        auth_header = {}

        # extend expiration of batch buffer to account for the duration of
        # this request
        if @is_batch_request
          auth_header = @resource.extend_batch_buffer(@token, @client_id)

        # update Authorization response header with new token
        else
          auth_header = @resource.create_new_auth_token(@client_id)
          print 'auth_header: ', auth_header

          # update the response header
          response.headers.merge!(auth_header)
          pp 'response.headers: ', response.headers
          # @resource.touch(:last_seen_at)
        end

      end # end lock

    end

  end

  def resource_class(m=nil)
    p 'resource_class'
    if m
      mapping = Devise.mappings[m]
    else
      mapping = Devise.mappings[resource_name] || Devise.mappings.values.first
    end

    mapping.to
  end


  private

  def mongoid?
    @resource < Mongoid::Document
  end

  def is_batch_request?(user, client_id)
    p 'is_batch_request? user.tokens: ', user.tokens[client_id]
    !params[:unbatch] &&
    user.tokens[client_id] &&
    user.tokens[client_id]['updated_at'] &&
    Time.parse(user.tokens[client_id]['updated_at'].to_s) > @request_started_at - DeviseTokenAuth.batch_request_buffer_throttle
  end
end
