module Authorization

export AbstractResource, AbstractClient, Permission,  # Types
       getpermission, setpermission!, setexpiry!,     # Get/set permissions
       haspermission, permissions_conflict,           # Other permission queries
       create!, read, update!, delete!,               # Actions on resources
       @add_required_fields_resource,  # Used when constructing concrete subtypes of AbstractResource
       @add_required_fields_client     # Used when constructing concrete subtypes of AbstractClient


using Dates

import Base.read, Base.delete!


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
# Get/set permissions

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


function setpermission!(client::C, resourcetype::DataType, p::Permission) where {C <: AbstractClient}
    !(resourcetype <: AbstractResource) && error("Type $(resourcetype) is not a subtype of AbstractResource.")
    client.type2permission[resourcetype] = p
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


################################################################################
# Permission queries

"""
Returns true if the client has permission to act on the resource according to the given action.

Action ust be one of :create, :read, :update, :delete.
"""
function haspermission(client::C, resource::R, action::Symbol) where {C <: AbstractClient, R <: AbstractResource}
    p = getpermission(client, resource)
    p == nothing                 && return false  # Permission not explicitly granted
    getfield(p, action) == false && return false  # Permission explicitly denied
    p.expiry < now()             && return false  # Permission has expired
    true
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


################################################################################
# Actions on resources

"Create resource. If successful return nothing, else return an error message as a String."
function create!(client::C, resource::R, val...) where {C <: AbstractClient, R <: AbstractResource}
    if !haspermission(client, resource, :create)
        return "$(typeof(client)) $(client.id) does not have permission to create $(typeof(resource)) $(resource.id)"
    end
    m = parentmodule(typeof(client))
    m._create!(client, resource, val...)
end


"Read resource. If successful return (true, value), else return (false, errormessage::String)."
function read(client::C, resource::R) where {C <: AbstractClient, R <: AbstractResource}
    if !haspermission(client, resource, :read)
        return (false, "$(typeof(client)) $(client.id) does not have permission to read $(typeof(resource)) $(resource.id)")
    end
    m = parentmodule(typeof(client))
    m._read(client, resource)
end


"Update resource. If successful return nothing, else return an error message as a String."
function update!(client::C, resource::R, val...) where {C <: AbstractClient, R <: AbstractResource}
    if !haspermission(client, resource, :update)
        return "$(typeof(client)) $(client.id) does not have permission to update $(typeof(resource)) $(resource.id)"
    end
    m = parentmodule(typeof(client))
    m._update!(client, resource, val...)
end


"Delete resource. If successful return nothing, else return an error message as a String."
function delete!(client::C, resource::R) where {C <: AbstractClient, R <: AbstractResource}
    if !haspermission(client, resource, :delete)
        return "$(typeof(client)) $(client.id) does not have permission to delete $(typeof(resource)) $(resource.id)"
    end
    m = parentmodule(typeof(client))
    m._delete!(client, resource)
end


end
