<p align="center">
  <img width="64" src="https://avatars2.githubusercontent.com/u/22204821?s=200&v=4" alt="Rehive Logo">
  <h1 align="center">DRF Rehive Extras</h1>
  <p align="center">Extra utilities for using Django REST Framework.</p>
</p>

## Features

- Python >= 3.6
- Django >= 3.0
- Generic views and mixins for all CRUD.
- Custom pagination that supports cursor and page based pagination.
- Integrated support for flex fields and django filters.
- Base serializers.
- Metadata, timestamp, and enum serializer fields.
- Schema generation support via drf-spectacular.
- Trusted origin (IP and country) resolution for requests behind Cloudflare.
- Shared permissions for Rehive services, such as the platform webhook origin check.
- Shared token authentication for Rehive services.

## Getting started

1. Install the package:

```sh
pip install drf-rehive-extras
```

2. Add "drf_rehive_extras" to your `INSTALLED_APPS` settings like this:

```python
INSTALLED_APPS = [
    # ...
    'drf_rehive_extras',
]
```

## Usage

### Schema generation

This library allows you to use `drf-spectacular` to generate Open API schemas that match the Rehive eveloped request/response format as defined by the `drf-rehive-extras` views/serializers.

To use schema generation, install `drf-spectacular` (in addition to `drf-rehive-extras` as described above):

```sh
pip install drf-spectacular[sidecar]
```

And add the following to the `INSTALLED_APPS` settings:

```python
INSTALLED_APPS = [
    # ...
    'drf_spectacular',
    'drf_spectacular_sidecar',
]
```

Finally, configure the `REST_FRAMEWORK` settings with:

```python
REST_FRAMEWORK = {
  'DEFAULT_SCHEMA_CLASS': 'drf_rehive_extras.schema.BaseAutoSchema',
}
```

The `schema.BaseAutoSchema` class also includes functionality to attach
additional documentation to the schema via yaml files.

To generate additional documentation, create a `docs.yaml` file in a `docs` folder in your Django app. The file should be formatted like this:

```yaml
app.views.ExampleView:
    GET:
        operationId:
        summary:
        description:
        x-code-samples:
            - lang:
              label:
              source: >
            - lang: Python
              label: Python SDK
              source: >
```

Then, in your `settings` file specify the above directory using the `ADDITIONAL_DOCS_DIRS` settings:

```python
import os

ADDITIONAL_DOCS_DIRS = [
    "/root/app/docs/",
]
```

### Pagination

This library adds extra pagination via `PageNumberPagination` and `CursorPagination` that can be used to generate paginated lists that return the results in the Rehive eveloped request/response format.

You can use them like this:

```python
from drf_rehive_extras.pagination import PageNumberPagination

class ExampleView(ListAPIView)
    pagination_class = PageNumberPagination
```

These pagination classes will be automatically applied to any views that inherit from the `drf-rehive-extras` generics and mixins.

### Serializers

This library includes base serializers that can be used to ensure all serializers share the same Rehive base:

- `BaseModelSerializer` : A DRF `ModelSerializer` that includes `rest_flex_fields` functionality.
- `ActionResponseSerializer` : A serializer that can be used to generate action responses.

### Serializers fields

This library adds extra serializer fields that can be used in DRF serializers:

- `MetadataField`
- `TimestampField`
- `EnumField`

These fields can be used like normal serializer fields.

### Views

This library includes a collection of generic views and mixins that can be used to ensure all views follow the same Rehive standard.

The generic views can be used like this:

```python
from drf_rehive_extras.generics import ListAPIView

class ListExampleModelView(ListAPIView):
    serializer_class = ExampleModelSerializer

    def get_queryset(self):
        if getattr(self, 'swagger_fake_view', False):
            return ExampleModel.objects.none()

        return ExampleModel.objects.all().order_by('-created')
```

The generic views allow for the customization of the serializer based on the method. This can be done by adding a `serializer_classes` attribute to the view:

```python
# Single shared request/response serializer.
serializer_classes = {
    "POST": ExampleModelRequestSerializer
}

# Multiple serializers, the first for the request and the second for the response.
serializer_classes = {
    "POST": (ExampleModelRequestSerializer, ExampleModelResponseSerializer,)
}
```

The generic views also support explicitly modifying the response status for a given method. This can be done via the `response_status_codes` attribute.

```python
response_status_codes = {"POST": status.HTTP_202_ACCEPTED}
```

If possible, all generic views will attempt to add a `_resource` and `_resource_id` to the request object. This will only be done if there is a single model instance and the instance contains a `RESOURCE` and/or `RESOURCE_ID` attribute.

Finally, in addition to the normal DRF generic views, the library contains an extra `ActionAPIView` that can be used for simple actions. These actions will default to a 200 response and will only ever return a `{"status": "success"}` response.

Usage is as follows:

```python
from drf_rehive_extras.generics import ActionAPIView
from drf_rehive_extras.serializers import ActionResponseSerializer

class ExampleActionView(ActionAPIView):
    serializer_class = ExampleActionSerializer
    serializer_classes = {
        "POST": (ExampleActionSerializer, ActionResponseSerializer,)
    }
```

### Authentication

`drf_rehive_extras.authentication` has the token authentication shared by Rehive services. It needs the Rehive SDK:

```sh
pip install drf-rehive-extras[auth]
```

`RehiveAuthentication` reads an `Authorization: Token <token>` header, validates the token against the Rehive API and checks `groups` (an empty list allows every group). A missing or malformed header is a 401. Services implement `get_user()` to turn the platform user into their own local user:

```python
import uuid

from rest_framework import exceptions
from drf_rehive_extras.authentication import RehiveAuthentication

from .models import Company, User


class UserAuthentication(RehiveAuthentication):
    def get_user(self, request, platform_user):
        try:
            company = Company.objects.get(
                identifier=platform_user['company'], active=True
            )
        except Company.DoesNotExist:
            raise exceptions.ValidationError(
                {"non_field_errors": ["Inactive company."]}
            )

        user, created = User.objects.get_or_create(
            identifier=uuid.UUID(platform_user['id']), company=company
        )
        return user


class AdminAuthentication(UserAuthentication):
    groups = ["admin", "service"]
```

The platform user is attached to the returned user as `user._platform_user`. The IP sent to Rehive as `X-Forwarded-For` comes from `drf_rehive_extras.ip.get_origin_ip`; override `get_forwarded_for()` to change it.

To migrate a service generated from `service-framework`, move the company and user lookup from `RehiveAuthentication.authenticate()` in `authentication.py` into `get_user()`, delete the rest of the copied code (`HeaderAuthentication`, `AuthenticationAPIException`, `_get_request_ips`, `_raise_exception`), and keep any service-specific subclasses as they are. `HeaderAuthentication.get_auth_header(request, name="secret")` still works for webhook secrets. Tests that patch `<module>.authentication.Rehive` should patch `drf_rehive_extras.authentication.Rehive` instead.

## Testing

```sh
pip install -e .[auth]
python runtests.py
```
