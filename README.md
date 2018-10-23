# Authorization.jl

A small but flexible API for controlling an __authenticated__ client's access to resources.

See the bottom of this README for use cases.


## Resources

All resources (subtypes of `AbstractResource`) have an `id`.
Resources may also have fields other than `id`.


## Clients

A client is a type (subtype of `AbstractClient`) that represents an entity wishing to access some resources.
Clients may represent users, web apps, data storage clients, etc.


## Permissions

A client's access to a resource is determined by its `Permission` for the resource.
The `Permission` type is defined as:

```julia
struct Permission
    create::Bool
    read::Bool
    update::Bool
    delete::Bool
    expiry::DateTime
end
```

Permissions created without an expiry are given an (almost) infinite expiry.

A client can loosely be thought of as a mapping from resources to `Permission`s.

More precisely, the mapping is a hierarchy of 3 maps.

As we move up the hierarchy:
- Each level maps a smaller set of resources to permissions than the previous level.
- The permissions override those specified at the previous level.

The levels are:

1. At the bottom of the hierarchy is the map from resource type to permission.
   This allows the same permission to be applied to all resources with the same type.
   For example a client may have read-only access to the entire local system.
   In this case the resources are directories and files and the associated permission is `Permission(false, true, false, false, expiry)`.

2. In the middle of the hierarchy is the map from resource ID pattern (`Regex`s) to permission.
   This mapping overrides the permissions specified in the type-to-permission mapping.
   Continuing our file system example, the same client could also have write access to a particular directory using this mapping.

3. At the top of the hierarchy is the map from resource ID to permission.
   This mapping allows access control for specific resources.

This framework allows both fine-grained and somewhat coarse access control within the same client, provided the permissions don't conflict within a level of the hierarchy (test for conflicts via `permissions_conflict(client, resourceid)`).

## Resource Access

Use `haspermission(client, resource, action)` to determine whether the client has permission to act (create/read/update/delete) on the resource.
Here the `action` is one of `:create`, `:read`, `:update`, `:delete`.

For convenience this package also provides `create!`, `read`, `update!` and `delete!`.
Each has the same signature, namely `(client, resource, args...)`.
Each works as follows:
- Check whether the client has permission to act on the resource.
- If so, act on the resource.
  - If all is well, return `(true, "")`
  - Else return `(false, message)`
- If not, return `(false, message)`


## Use Cases

### Data Storage

In bucket storage, data is stored as objects and objects are grouped into buckets.
The [`BucketStores`]() package defines a client for bucket storage and allows the storage backend to be swapped without changing any code.

Examples of storage backends include:
- [`LocalDiskStores.jl`](), which uses the local file system to store objects (files) in buckets (directories).
- [`GCPBucketStores.jl`](), which uses Google Cloud Storage.

This authorization framework is used to control access to buckets and objects.


### Web app authorization

Authorization.jl can be used to implement web-app sessions.

Suppose a user's access is determined by his/her subscription to an app. 

Then, for example, `setpermission!(client, App, permission)` sets permissions for all resources related to the app with type `App`.
Also, `setexpiry(client, expiry)` can be used to set an expiry on all resources to which the client has access.
The client can then be used as the session object.
