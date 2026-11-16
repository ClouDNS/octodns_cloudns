"""Register a DS record only on octoDNS versions that lack one."""


def ensure_ds_type():
    try:
        from octodns.record import DsRecord  # noqa: F401
        return
    except ImportError:
        pass
    from octodns.record import Record
    from octodns.record.base import ValuesMixin
    from octodns.equality import EqualityTupleMixin

    class DsValue(EqualityTupleMixin, dict):
        @classmethod
        def validate(cls, data, _type):
            from .ds import DsCodec
            values = data if isinstance(data, (list, tuple)) else (data,)
            reasons = []
            for value in values:
                try:
                    DsCodec.key(value)
                except Exception:
                    reasons.append('invalid DS value')
            return reasons

        @classmethod
        def process(cls, values):
            return [cls(v) for v in values]

        def __init__(self, value):
            from .ds import DsCodec
            super().__init__(DsCodec.value(DsCodec.key(value)))

        @property
        def data(self):
            return self

        @property
        def key_tag(self):
            return self['key_tag']

        @property
        def algorithm(self):
            return self['algorithm']

        @property
        def digest_type(self):
            return self['digest_type']

        @property
        def digest(self):
            return self['digest']

        def _equality_tuple(self):
            return (self.key_tag, self.algorithm, self.digest_type, self.digest)

        @property
        def rdata_text(self):
            return '{} {} {} {}'.format(self.key_tag, self.algorithm, self.digest_type, self.digest)

    class DsRecord(ValuesMixin, Record):
        _type = 'DS'
        _value_type = DsValue

    Record.register_type(DsRecord)
