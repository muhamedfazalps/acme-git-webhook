from pathlib import Path

import dns.name
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rdtypes
import dns.rdtypes.TXT
import dns.zone


def _resolve_zone_path(
    repos_path: Path,
    domain: str,
    zone_path: str,
    suffix: str,
) -> Path | None:
    clean = domain.removeprefix("_acme-challenge.").removeprefix("*.")
    labels = clean.split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        path = repos_path / zone_path / f"{candidate}{suffix}"
        if path.exists():
            return path
    return None


def add_txt_record(
    repos_path: Path,
    domain: str,
    token: str,
    zone_path: str,
    suffix: str,
) -> str:
    zone_file = _resolve_zone_path(repos_path, domain, zone_path, suffix)
    if zone_file is None:
        raise FileNotFoundError(
            f"No zone file found for domain '{domain}' in {repos_path / zone_path}"
        )

    zone = dns.zone.from_file(str(zone_file))

    acme_name = dns.name.from_text(f"_acme-challenge.{domain}")
    rdtype = dns.rdatatype.TXT
    rdclass = dns.rdataclass.IN

    rdataset = zone.get_rdataset(acme_name, rdtype)
    if rdataset is None:
        rdataset = dns.rdataset.Rdataset(rdclass, rdtype)
    else:
        rdataset.clear()

    rdataset.add(dns.rdtypes.TXT.TXT(rdclass, rdtype, [token.encode()]))
    zone.replace_rdataset(acme_name, rdataset)
    zone.to_file(str(zone_file))
    return str(zone_file)


def remove_txt_record(
    repos_path: Path,
    domain: str,
    zone_path: str,
    suffix: str,
) -> str | None:
    zone_file = _resolve_zone_path(repos_path, domain, zone_path, suffix)
    if zone_file is None:
        return None

    zone = dns.zone.from_file(str(zone_file))
    acme_name = dns.name.from_text(f"_acme-challenge.{domain}")

    try:
        zone.delete_rdataset(acme_name, dns.rdatatype.TXT)
        zone.to_file(str(zone_file))
        return str(zone_file)
    except KeyError:
        return None
