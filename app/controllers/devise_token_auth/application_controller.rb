module DeviseTokenAuth
  class ApplicationController < DeviseController
    include DeviseTokenAuth::Concerns::SetUserByToken

    def resource_data(opts={})
      response_data = opts[:resource_json] || @resource.as_json(:except => :_id)
      if is_json_api
        p 'is_json_api'
        response_data['type'] = @resource.class.name.parameterize
      end
      p 'resource_data response_data: ', response_data
      response_data
    end

    def resource_errors
      return @resource.errors.to_hash.merge(full_messages: @resource.errors.full_messages)
    end

    protected

    def params_for_resource(resource)
      print 'params_for_resource: ', resource
      print 'devise_parameter_sanitizer.instance_values[\'permitted\'][resource]: ', devise_parameter_sanitizer.instance_values['permitted'][resource]
      devise_parameter_sanitizer.instance_values['permitted'][resource].each do |type|
        params[type.to_s] ||= request.headers[type.to_s] unless request.headers[type.to_s].nil?
      end
      devise_parameter_sanitizer.instance_values['permitted'][resource]
    end

    def resource_class(m=nil)
      if m
        mapping = Devise.mappings[m]
      else
        mapping = Devise.mappings[resource_name] || Devise.mappings.values.first
      end

      mapping.to
    end

    def is_json_api
      p 'is_json_api start 1'
      return false unless defined?(ActiveModel::Serializer)
      p 'is_json_api start 2'
      return ActiveModel::Serializer.setup do |config|
        config.adapter == :json_api
      end if ActiveModel::Serializer.respond_to?(:setup)
      p 'is_json_api 3'
      return ActiveModelSerializers.config.adapter == :json_api
    end

  end
end
