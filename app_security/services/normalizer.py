def normalize_vulners_software_audit(data, query_value):
    """Normalise la reponse de software_audit Vulners vers le format interne."""
    results = []

    if not data:
        return results

    vulnerabilities = []

    # Plusieurs formats possibles selon l’endpoint/réponse.
    if isinstance(data, dict):
        if "data" in data and isinstance(data["data"], dict):
            vulnerabilities = data["data"].get("vulnerabilities", []) or data["data"].get("search", [])
        elif "vulnerabilities" in data:
            vulnerabilities = data.get("vulnerabilities", [])
        elif "search" in data:
            vulnerabilities = data.get("search", [])

    for item in vulnerabilities:
        cve_id = item.get("id") or item.get("cve")
        if not cve_id:
            cvelist = item.get("cvelist") or []
            cve_id = cvelist[0] if cvelist else None

        if not cve_id or not str(cve_id).startswith("CVE-"):
            continue

        description = item.get("description") or item.get("title") or ""

        score = None
        severity = None

        cvss = item.get("cvss", {})
        if isinstance(cvss, dict):
            score = cvss.get("score")
            severity = cvss.get("severity")

        results.append({
            "source_api": "vulners",
            "cve_id": cve_id,
            "description": description,
            "severity": severity,
            "score": score,
            "published": item.get("published"),
            "query_value": query_value,
            "correlation_type": "software_audit",
            "raw_payload": item,
        })

    return results

def normalize_nvd(data, query):
    """Normalise la reponse de lAPI NVD vers le format interne."""
    results = []

    if not data:
        return results

    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})

        cve_id = cve.get("id")
        published = cve.get("published")

        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        severity = None
        score = None

        metrics = cve.get("metrics", {})

        if metrics.get("cvssMetricV31"):
            metric = metrics["cvssMetricV31"][0]
            severity = metric.get("cvssData", {}).get("baseSeverity")
            score = metric.get("cvssData", {}).get("baseScore")

        elif metrics.get("cvssMetricV30"):
            metric = metrics["cvssMetricV30"][0]
            severity = metric.get("cvssData", {}).get("baseSeverity")
            score = metric.get("cvssData", {}).get("baseScore")

        elif metrics.get("cvssMetricV2"):
            metric = metrics["cvssMetricV2"][0]
            severity = metric.get("baseSeverity")
            score = metric.get("cvssData", {}).get("baseScore")

        results.append({
            "source_api": "nvd",
            "cve_id": cve_id,
            "description": description,
            "severity": severity,
            "score": score,
            "published": published,
            "query_value": query["query_value"],
            "correlation_type": query["correlation_type"],
            "raw_payload": item,
        })

    return results

def normalize_vulners(data, query):
    """Normalise la reponse Lucene de Vulners et deduplique par cve_id."""
    results = []

    if not data:
        return results

    for item in data.get("data", {}).get("search", []):
        source = item.get("_source", {})

        # 1) cas idéal : l'id est déjà une CVE
        if source.get("id", "").startswith("CVE-"):
            cve_ids = [source.get("id")]
        else:
            # 2) sinon on essaye de récupérer la liste des CVE liées
            cve_ids = source.get("cvelist") or []

        if not cve_ids:
            continue

        for cve_id in cve_ids:
            if not str(cve_id).startswith("CVE-"):
                continue

            results.append({
                "source_api": "vulners",
                "cve_id": cve_id,
                "description": source.get("description") or source.get("title") or "",
                "severity": source.get("cvss", {}).get("severity") if isinstance(source.get("cvss"), dict) else None,
                "score": source.get("cvss", {}).get("score") if isinstance(source.get("cvss"), dict) else None,
                "published": source.get("published"),
                "query_value": query,
                "correlation_type": "lucene_cve_only",
                "raw_payload": item,
            })

    # suppression des doublons par cve_id
    unique = {}
    for vuln in results:
        unique[vuln["cve_id"]] = vuln

    return list(unique.values())

def normalize_circl(data):
    """Normalise la reponse de lAPI CIRCL vers le format interne."""
    results = []

    if not data:
        return results

    vulnerabilities = []

    if isinstance(data, dict):
        if "data" in data:
            vulnerabilities = data.get("data", [])

        elif "results" in data:
            for source_name, items in data.get("results", {}).items():
                for entry in items:
                    if isinstance(entry, list) and len(entry) >= 2:
                        vulnerabilities.append(entry[1])
                    elif isinstance(entry, dict):
                        vulnerabilities.append(entry)

    elif isinstance(data, list):
        vulnerabilities = data
    else:
        return results

    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue

        cve_id = (
            item.get("id")
            or item.get("cve")
            or item.get("vulnerability")
            or item.get("CVE")
        )

        description = ""
        descriptions = item.get("descriptions", [])
        if isinstance(descriptions, list):
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

        if not description:
            description = (
                item.get("summary")
                or item.get("description")
                or item.get("title")
                or ""
            )

        published = (
            item.get("Published")
            or item.get("published")
            or item.get("created")
        )

        score = (
            item.get("cvss")
            or item.get("cvss_base_score")
            or item.get("score")
        )

        if not score:
            metrics = item.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31:
                score = cvss_v31[0].get("cvssData", {}).get("baseScore")

        severity = item.get("severity") or ""

        if not severity:
            metrics = item.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            if cvss_v31:
                severity = cvss_v31[0].get("cvssData", {}).get("baseSeverity", "")

        results.append({
            "source_api": "circl",
            "cve_id": cve_id,
            "description": description,
            "severity": severity,
            "score": score,
            "published": published,
            "query_value": None,
            "correlation_type": "cpe_or_vendor_product",
            "raw_payload": item,
        })

    return results

def normalize_osv(data, package, ecosystem, version):
    """Normalise la reponse de lAPI OSV vers le format interne."""
    results = []

    if not data:
        return results

    for vuln in data.get("vulns", []):
        results.append({
            "source_api": "osv",
            "cve_id": vuln.get("id"),
            "description": vuln.get("summary"),
            "severity": None,
            "score": None,
            "published": vuln.get("published"),
            "query_value": f"{package}:{ecosystem}:{version}",
            "correlation_type": "package_lookup",
            "raw_payload": vuln,
        })

    return results