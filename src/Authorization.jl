module Authorization

export AbstractResource, AbstractClient, Permission,  # Types
       @add_required_fields_resource, @add_required_fields_client, 
       create!, read, update!, delete!,               # Verbs
       getpermission, setpermission!, setexpiry!,     # get/set
       haspermission,  # Query permission
       permissions_conflict


using Dates


################################################################################
# Types

struct Permission
    create::Bool
    read::Bool
    update::Bool
    delete::Bool
    expiry::DateTime
end

Permission(c, r, u, d) = Permission(c, r, u, d, now() + Year(1000))  # Effectively no expiry


abstract type AbstractResource end


"""
Add fields that are required by all concrete subtypes of AbstractResource.

Use this macro when defining a concrete subtype of AbstractResource.

Example 1 - No other fields

  struct MyResource <: AbstractResource
      @add_required_fields_resource  # Fields that all resources require
  end

Example 2 - The resource type contains fields that are specific to the type

  struct MyOtherResource <: AbstractResource
      @add_required_fields_resource  # Fields that all resources require
      otherfield1::Int               # Field that is specific to MyOtherResource
      otherfield2::String            # Field that is specific to MyOtherResource
  end
"""
macro add_required_fields_resource()
    return esc(:(id::String))
end


abstract type AbstractClient end


"""
Add fields that are required by all concrete subtypes of AbstractClient.

Use this macro when defining a concrete subtype of AbstractClient.

Example 1 - No other fields

  struct MyClient <: AbstractClient
      @add_required_fields_client  # Fields that all clients require
  end

Example 2 - The client type contains fields that are specific to the type

  struct MyOtherClient <: AbstractClient
      @add_required_fields_client  # Fields that all client require
      otherfield1::Int             # Field that is specific to MyOtherClient
      otherfield2::String          # Field that is specific to MyOtherClient
  end
"""
macro add_required_fields_client()
    return esc(:(
                 id::String;
                 id2permission::Dict{String, Permission};        # Resource ID => Permission
                 idpattern2permission::Dict{Regex, Permission};  # Resource ID pattern => Permission
                 type2permission::Dict{DataType, Permission};    # Resource type => Permission
                ))
end

################################################################################
# Verbs

function create!(client::C, resource::R, args...) where {C <: AbstractClient, R <: AbstractResource}
    if !haspermission(client, resource, :create)
        return false, "$(typeof(client)) $(client.id) does not have permission to create $(typeof(resource)) $(resource.id)"
    end
    m = parentmodule(typeof(resource))
    m._create!(resource, args...)
end


function read(client::C, resource::R, args...) where {C <: AbstractClient, R <: AbstractResource}
    if !haspermission(client, resource, :read)
        return nothing, "$(typeof(client)) $(client.id) does not have permission to read $(typeof(resource)) $(resource.id)"
    end
    m = parentmodule(typeof(resource))
    m._read(resource, args...)
end


function update!(client::C, resource::R, args...) where {C <: AbstractClient, R <: AbstractResource}
    if !haspermission(client, resource, :update)
        return false, "$(typeof(client)) $(client.id) does not have permission to update $(typeof(resource)) $(resource.id)"
    end
    m = parentmodule(typeof(resource))
    m._update!(resource, args...)
end


function delete!(client::C, resource::R, args...) where {C <: AbstractClient, R <: AbstractResource}
    if !haspermission(client, resource, :delete)
        return false, "$(typeof(client)) $(client.id) does not have permission to delete $(typeof(resource)) $(resource.id)"
    end
    m = parentmodule(typeof(resource))
    m._delete!(resource, args...)
end

################################################################################
# Conveniences

"""
Returns the Permission object for client-resource combination if it exists, else returns nothing.
"""
function getpermission(client::C, resource::R) where {C <: AbstractClient, R <: AbstractResource}
    # Get permission by resource ID
    rid = resource.id
    haskey(client.id2permission, rid) && return client.id2permission[rid]

    # Else get permission by resource ID pattern
    result = nothing
    for (patt, p) in client.idpattern2permission
        if match(patt, rid) != nothing
            if typeof(result) == Permission  # A matching Permission has already been found
                error("There is more than 1 pattern that matches $(typeof(resource)) $(resource.id). Potentially conflicting permissions.")
            else
                result = p
            end
        end
    end
    result != nothing && return result

    # Else get permission by resource type
    rtype = typeof(resource)
    haskey(client.type2permission, rtype) && return client.type2permission[rtype]

    # Else no Permission object exists...return nothing
    nothing
end


function setpermission!(client::C, resourceid::String, p::Permission) where {C <: AbstractClient}
    client.id2permission[resourceid] = p
end


function setpermission!(client::C, resourceid_pattern::Regex, p::Permission) where {C <: AbstractClient}
    client.idpattern2permission[resourceid_pattern] = p
end


function setpermission!(client::C, R::DataType, p::Permission) where {C <: AbstractClient}
    !(R <: AbstractResource) && error("Type $(R) is not a subtype of AbstractResource.")
    client.type2permission[resourcetype] = p
end


"""
Returns true if the client has permission to act on the resource according to the given verb.

Verb must be one of :create, :read, :update, :delete.
"""
function haspermission(client::C, resource::R, verb::Symbol) where {C <: AbstractClient, R <: AbstractResource}
    p = getpermission(client, resource)
    p == nothing               && return false  # Permission not explicitly granted
    getfield(p, verb) == false && return false  # Permission explicitly denied
    p.expiry < now()           && return false  # Permission has expired
    true
end


"""
Set the expiry of every permission of the client to the given expiry.
"""
function setexpiry!(client::C, expry::DateTime) where {C <: AbstractClient}
    for d in (client.id2permission, client.idpattern2permission, client.type2permission)
        for (k, p) in d
            d[k] = Permission(p.create, p.read, p.update, p.delete, expry)
        end
    end
end


"Returns true if more than one resource ID pattern matches the resource ID."
function permisssions_conflict(client::C, resourceid::String) where {C <: AbstractClient}
    nmatches = 0
    for (patt, p) in client.idpattern2permission
        if match(patt, resourceid) != nothing
            nmatches += 1
        end
    end
    nmatches > 1  # More than 1 pattern matches the resource id
end

end
