from rest_framework import serializers
from rest_framework.fields import CreateOnlyDefault, empty
from rest_flex_fields import FlexFieldsModelSerializer


class BaseModelSerializer(FlexFieldsModelSerializer):

    def get_uniqueness_extra_kwargs(self, field_names, declared_fields,
                                    extra_kwargs):
        """
        Make the defaults DRF adds for unique constraint fields create-only.

        Since DRF 3.16, a field that is part of a `UniqueConstraint` gets a
        `default` (its model default, or None/'' when it is nullable/blank)
        so the uniqueness validator can run when the field is omitted on
        create. A plain default is also applied on a full (PUT) update, so an
        omitted field would be overwritten with it (e.g. `primary=False`,
        `slug=None`). Wrapping it in `CreateOnlyDefault` keeps the create
        behaviour and leaves omitted fields untouched on update, as DRF 3.14
        did. Defaults set explicitly in `Meta.extra_kwargs` are left as is.
        """
        explicit_defaults = {
            name for name, kwargs in extra_kwargs.items()
            if 'default' in kwargs
        }
        extra_kwargs, hidden_fields = super().get_uniqueness_extra_kwargs(
            field_names, declared_fields, extra_kwargs
        )
        for name, kwargs in extra_kwargs.items():
            default = kwargs.get('default', empty)
            if (name in explicit_defaults
                    or default is empty
                    or isinstance(default, CreateOnlyDefault)):
                continue
            kwargs['default'] = CreateOnlyDefault(default)
        return extra_kwargs, hidden_fields


class ActionResponseSerializer(serializers.Serializer):
    """
    This serializer can be used if only a `status` is required in the response.
    """

    status = serializers.CharField(required=True)
