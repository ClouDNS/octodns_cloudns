"""DS codec and per-ID reconciliation for DNS hosting (not registrar DNSSEC)."""

import re
from collections import defaultdict

from octodns.provider import ProviderException


class DsCodec:
    @staticmethod
    def key(value):
        try:
            numbers = tuple(
                int(value[field]) for field in ("key_tag", "algorithm", "digest_type")
            )
            if not (
                0 <= numbers[0] <= 65535
                and all(0 <= number <= 255 for number in numbers[1:])
            ):
                raise ValueError()
            digest = value["digest"].strip().lower()
            if not re.fullmatch(r"(?:[0-9a-f]{2})+", digest):
                raise ValueError()
            length = {1: 40, 2: 64, 4: 96}.get(numbers[2])
            if length is not None and len(digest) != length:
                raise ValueError()
            return (*numbers, digest)
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ProviderException("Invalid or incomplete DS value") from None

    @classmethod
    def from_row(cls, row):
        return cls.value(cls.key(dict(row, digest=row.get("record"))))

    @staticmethod
    def value(key):
        return dict(zip(("key_tag", "algorithm", "digest_type", "digest"), key))

    @classmethod
    def fields(cls, value):
        key_tag, algorithm, digest_type, digest = cls.key(value)
        return {
            "key_tag": key_tag,
            "algorithm": algorithm,
            "digest_type": digest_type,
            "record": digest,
        }

    @staticmethod
    def active(row):
        return str(row.get("status", 1)) == "1"

    @staticmethod
    def validate_row(row):
        if any(
            row.get(field)
            for field in ("geodns-location", "geodns-code", "geodns-location-code")
        ):
            raise ProviderException("GeoDNS DS rows are not supported")


def operations(rows, record, deleting=False):
    """Validate the whole bucket, then return adds, mods and deletes.

    Retain equal values first. Pair changed values with remaining IDs for
    in-place updates; add surplus desired values before removing old values.
    Inactive rows are intentionally outside the managed active bucket.
    """
    grouped = defaultdict(list)
    for record_id, row in rows.items():
        if row["type"] != "DS" or row["host"] != record.name:
            continue
        if not DsCodec.active(row):
            continue
        DsCodec.validate_row(row)
        key = DsCodec.key(DsCodec.from_row(row))
        try:
            int(row["ttl"])
        except (KeyError, TypeError, ValueError):
            raise ProviderException("Invalid DS row TTL") from None
        grouped[key].append((row.get("id", record_id), row))

    wanted = {} if deleting else {DsCodec.key(v): v for v in record.values}
    mods, spare = [], []
    for key, bucket in sorted(grouped.items()):
        if key in wanted:
            record_id, row = bucket.pop(0)
            value = wanted.pop(key)
            if int(row["ttl"]) != record.ttl:
                mods.append(("mod", record_id, DsCodec.fields(value)))
        spare.extend(bucket)
    new = [value for _, value in sorted(wanted.items())]
    paired = min(len(spare), len(new))
    mods.extend(("mod", spare[i][0], DsCodec.fields(new[i])) for i in range(paired))
    adds = [("add", None, DsCodec.fields(value)) for value in new[paired:]]
    deletes = [("delete", record_id, None) for record_id, _ in spare[paired:]]
    return adds + mods + deletes
