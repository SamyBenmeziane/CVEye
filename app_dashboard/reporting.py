from io import BytesIO
from pathlib import Path
import re
from xml.sax.saxutils import escape

from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app_core.models import Service
from .risk_utils import compute_severity_counts_risk_label, normalize_severity_label


def sanitize_filename(value):
    """Remplace les caractères non alphanumériques par des tirets pour produire un nom de fichier safe."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value or "").strip("-") or "machine"


def _safe_text(value):
    """Échappe les caractères XML spéciaux et convertit les sauts de ligne en balises <br/> pour ReportLab."""
    return escape(str(value or "")).replace("\n", "<br/>")


def _build_styles():
    """Construit et retourne tous les styles de paragraphes ReportLab utilisés dans le rapport PDF."""
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontSize=22,
            leading=26,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=14,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SectionTitle",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1d4ed8"),
            spaceBefore=6,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="MetaLine",
            parent=styles["BodyText"],
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#475569"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#334155"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="BodyTiny",
            parent=styles["BodyText"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748b"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="Footer",
            parent=styles["BodyText"],
            fontSize=8,
            alignment=TA_RIGHT,
            textColor=colors.HexColor("#64748b"),
        )
    )
    return styles


def _build_summary_table(scan_data):
    """Construit le tableau résumé d'un scan pour le PDF : statut, dates, durée, ports et vulnérabilités."""
    rows = [
        ["Statut", scan_data["status_label"]],
        ["Date début", scan_data["date_debut"]],
        ["Date fin", scan_data["date_fin"]],
        ["Durée", scan_data["duration"]],
        ["Ports ouverts", str(scan_data["ports_ouverts"])],
        ["Services détectés", str(scan_data["service_count"])],
        ["Vulnérabilités", str(scan_data["vulnerability_count"])],
        ["Risque", scan_data["risk_label"]],
    ]

    table = Table(rows, colWidths=[5.2 * cm, 10.8 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e2e8f0")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _build_severity_table(scan_data):
    """Construit le tableau de distribution des sévérités pour le rapport PDF."""
    rows = [["Critique", "Élevée", "Moyenne", "Faible", "Inconnue"]]
    rows.append(
        [
            str(scan_data["severity_counts"]["Critique"]),
            str(scan_data["severity_counts"]["Élevée"]),
            str(scan_data["severity_counts"]["Moyenne"]),
            str(scan_data["severity_counts"]["Faible"]),
            str(scan_data["severity_counts"]["Inconnue"]),
        ]
    )

    table = Table(rows, colWidths=[3.2 * cm] * 5)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#fee2e2")),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#fed7aa")),
                ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#fef3c7")),
                ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#dcfce7")),
                ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#e2e8f0")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return table


def _severity_color(label):
    """Retourne le code couleur hexadécimal associé à un niveau de sévérité CVE."""
    if label == "Critique":
        return "#b91c1c"
    if label == "Élevée":
        return "#c2410c"
    if label == "Moyenne":
        return "#a16207"
    if label == "Faible":
        return "#15803d"
    return "#475569"


def _build_recommendations(scan_data):
    """Génère jusqu'à 4 recommandations textuelles adaptées aux résultats du scan."""
    recommendations = []

    if scan_data["severity_counts"]["Critique"] > 0:
        recommendations.append("Prioriser immédiatement les CVE critiques et planifier les correctifs sans délai.")
    if scan_data["severity_counts"]["Élevée"] > 0:
        recommendations.append("Traiter rapidement les services exposés avec vulnérabilités élevées.")
    if scan_data["ports_ouverts"] > 0:
        recommendations.append("Vérifier que chaque port exposé est strictement nécessaire et filtrer les accès inutiles.")
    if scan_data["service_count"] > 0:
        recommendations.append("Confirmer les versions des services détectés et appliquer les mises à jour de sécurité éditeur.")
    if scan_data["vulnerability_count"] == 0:
        recommendations.append("Aucune vulnérabilité corrélée n'a été détectée sur ce scan ; maintenir la surveillance périodique.")
    if scan_data["status_label"] == "Hors ligne":
        recommendations.append("Vérifier la disponibilité de la machine ou la connectivité réseau avant interprétation du résultat.")

    return recommendations[:4]


def _build_cover_table(target, generated_by, generated_at, scan_count):
    """Construit le tableau de couverture du rapport PDF avec les informations de la cible."""
    rows = [
        ["Machine", target.adresse],
        ["Type", target.get_type_cible_display()],
        ["Description", target.description or "Aucune description"],
        ["Nombre de scans", str(scan_count)],
        ["Généré par", generated_by.username],
        ["Généré le", generated_at],
    ]
    table = Table(rows, colWidths=[4.5 * cm, 11.5 * cm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eff6ff")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )
    return table


def _draw_page_footer(canvas, doc):
    """Dessine le pied de page sur chaque page du PDF : ligne, nom de l'application et numéro de page."""
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#cbd5e1"))
    canvas.line(doc.leftMargin, 1.15 * cm, A4[0] - doc.rightMargin, 1.15 * cm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(doc.leftMargin, 0.75 * cm, "CVEye - Rapport de sécurité")
    canvas.drawRightString(A4[0] - doc.rightMargin, 0.75 * cm, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def _format_datetime(value):
    """Formate une date Django en heure locale au format 'YYYY-MM-DD HH:MM:SS', ou 'N/A' si nulle."""
    if not value:
        return "N/A"
    local_value = timezone.localtime(value)
    return local_value.strftime("%Y-%m-%d %H:%M:%S")


def _build_scan_data(scan):
    """Rassemble et structure toutes les données d'un scan nécessaires à la génération du rapport PDF."""
    services = (
        Service.objects.filter(scan=scan)
        .prefetch_related("vulnerabilities")
        .order_by("port")
    )

    severity_counts = {
        "Critique": 0,
        "Élevée": 0,
        "Moyenne": 0,
        "Faible": 0,
        "Inconnue": 0,
    }
    service_rows = []
    vulnerability_count = 0

    # On reconstruit les compteurs a partir des services pour garder un rapport autonome
    for service in services:
        vulnerabilities = []
        for vulnerability in service.vulnerabilities.all():
            severity_label = normalize_severity_label(vulnerability.severity)
            severity_counts[severity_label] += 1
            vulnerability_count += 1
            vulnerabilities.append(
                {
                    "cve_id": vulnerability.cve_id,
                    "severity": severity_label,
                    "score": vulnerability.score,
                    "description": vulnerability.description or "Description indisponible.",
                }
            )

        service_rows.append(
            {
                "port": service.port,
                "protocol": service.protocole.upper(),
                "service": service.nom_service or "unknown",
                "product": service.produit or "N/A",
                "version": service.version or "N/A",
                "banner": service.banniere or "",
                "headers": service.en_tetes if isinstance(service.en_tetes, dict) else {},
                "vulnerabilities": vulnerabilities,
            }
        )

    duration = "N/A"
    if scan.date_debut and scan.date_fin:
        duration = f"{max(0, int((scan.date_fin - scan.date_debut).total_seconds()))} s"
    elif scan.date_debut and scan.statut in {"en_cours", "en_attente"}:
        duration = f"{max(0, int((timezone.now() - scan.date_debut).total_seconds()))} s (en cours)"

    if scan.server_hs:
        status_label = "Hors ligne"
    elif scan.statut == "complete":
        status_label = "Complété"
    elif scan.statut == "echoue":
        status_label = "Échoué"
    else:
        status_label = scan.statut

    return {
        "scan": scan,
        "date_debut": _format_datetime(scan.date_debut),
        "date_fin": _format_datetime(scan.date_fin),
        "duration": duration,
        "status_label": status_label,
        "ports_ouverts": scan.ports_ouverts,
        "service_count": len(service_rows),
        "vulnerability_count": vulnerability_count,
        "severity_counts": severity_counts,
        "risk_label": compute_severity_counts_risk_label(severity_counts),
        "service_rows": service_rows,
        "error_message": scan.message_erreur or "",
    }


def build_target_report_filename(target, scan_count):
    """Construit le nom de fichier du rapport PDF en combinant l'adresse de la cible et le nombre de scans."""
    suffix = "dernier-scan" if scan_count == 1 else f"{scan_count}-derniers-scans"
    return f"rapport-{sanitize_filename(target.adresse)}-{suffix}.pdf"


def generate_target_report_pdf(target, scans, generated_by):
    """Génère et retourne le contenu binaire du rapport PDF de sécurité pour une cible.

    Inclut une page de couverture, une synthèse globale et une section détaillée
    par scan (résumé, sévérités, recommandations, services et CVE associés).
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=1.4 * cm,
        bottomMargin=1.2 * cm,
        leftMargin=1.3 * cm,
        rightMargin=1.3 * cm,
    )
    styles = _build_styles()
    story = []
    generated_at = timezone.localtime(timezone.now()).strftime("%Y-%m-%d %H:%M:%S")
    logo_path = Path(__file__).resolve().parent / "static" / "app_dashboard" / "img" / "logo_cveye.png"

    if not scans:
        story.append(Paragraph("Aucun scan disponible pour cette machine.", styles["BodyText"]))
        doc.build(story, onFirstPage=_draw_page_footer, onLaterPages=_draw_page_footer)
        return buffer.getvalue()

    scan_data_list = [_build_scan_data(scan) for scan in scans]
    total_services = sum(item["service_count"] for item in scan_data_list)
    total_vulnerabilities = sum(item["vulnerability_count"] for item in scan_data_list)
    max_risk = "Faible"
    for level in ("Critique", "Élevé", "Moyen"):
        if any(item["risk_label"] == level for item in scan_data_list):
            max_risk = level
            break

    if logo_path.exists():
        story.append(Image(str(logo_path), width=4.5 * cm, height=1.35 * cm))
        story.append(Spacer(1, 0.2 * cm))

    story.append(Paragraph("Rapport de sécurité CVEye", styles["ReportTitle"]))
    story.append(Paragraph("Synthèse téléchargeable par machine", styles["MetaLine"]))
    story.append(Spacer(1, 0.25 * cm))
    story.append(_build_cover_table(target, generated_by, generated_at, len(scan_data_list)))
    story.append(Spacer(1, 0.35 * cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1")))
    story.append(Spacer(1, 0.3 * cm))

    story.append(Paragraph("Synthèse globale", styles["SectionTitle"]))
    story.append(
        Paragraph(
            f"Nombre de scans inclus : <b>{len(scan_data_list)}</b><br/>"
            f"Total des services détectés : <b>{total_services}</b><br/>"
            f"Total des vulnérabilités détectées : <b>{total_vulnerabilities}</b><br/>"
            f"Niveau de risque maximal observé : <b>{max_risk}</b>",
            styles["BodyText"],
        )
    )
    story.append(Spacer(1, 0.35 * cm))

    for index, scan_data in enumerate(scan_data_list, start=1):
        story.append(Paragraph(f"Scan {index} - {scan_data['date_debut']}", styles["SectionTitle"]))
        story.append(_build_summary_table(scan_data))
        story.append(Spacer(1, 0.2 * cm))
        story.append(_build_severity_table(scan_data))
        story.append(Spacer(1, 0.25 * cm))

        recommendations = _build_recommendations(scan_data)
        if recommendations:
            story.append(Paragraph("Recommandations", styles["SectionTitle"]))
            for recommendation in recommendations:
                story.append(Paragraph(f"- {_safe_text(recommendation)}", styles["BodySmall"]))
            story.append(Spacer(1, 0.2 * cm))

        if scan_data["error_message"]:
            story.append(
                Paragraph(
                    f"<b>Message d'erreur :</b> {_safe_text(scan_data['error_message'])}",
                    styles["BodyText"],
                )
            )
            story.append(Spacer(1, 0.2 * cm))

        if scan_data["service_rows"]:
            story.append(Paragraph("Services et expositions détectés", styles["SectionTitle"]))
            for service in scan_data["service_rows"]:
                story.append(
                    Paragraph(
                        f"<b>Port {service['port']}/{service['protocol']}</b> - "
                        f"{_safe_text(service['service'])} | Produit : {_safe_text(service['product'])} | "
                        f"Version : {_safe_text(service['version'])}",
                        styles["BodyText"],
                    )
                )

                if service["banner"]:
                    story.append(Paragraph(f"Bannière : {_safe_text(service['banner'])}", styles["BodySmall"]))

                if service["headers"]:
                    headers_text = ", ".join(f"{key}: {value}" for key, value in service["headers"].items())
                    story.append(Paragraph(f"En-têtes : {_safe_text(headers_text)}", styles["BodySmall"]))

                if service["vulnerabilities"]:
                    for vulnerability in service["vulnerabilities"]:
                        score_label = (
                            f"{vulnerability['score']:.1f}"
                            if vulnerability["score"] is not None
                            else "N/A"
                        )
                        severity_color = _severity_color(vulnerability["severity"])
                        story.append(
                            Paragraph(
                                f"- <b>{_safe_text(vulnerability['cve_id'])}</b> | "
                                f"Sévérité : <font color='{severity_color}'>{_safe_text(vulnerability['severity'])}</font> | "
                                f"Score : {score_label}<br/>"
                                f"{_safe_text(vulnerability['description'])}",
                                styles["BodySmall"],
                            )
                        )
                else:
                    story.append(Paragraph("- Aucune vulnérabilité détectée.", styles["BodySmall"]))

                story.append(Spacer(1, 0.15 * cm))
        else:
            story.append(Paragraph("Aucun service détecté pour ce scan.", styles["BodyText"]))

        story.append(Spacer(1, 0.1 * cm))
        story.append(
            Paragraph(
                "Ce rapport est généré automatiquement à partir des données du dernier état du scan conservé dans CVEye.",
                styles["BodyTiny"],
            )
        )

        if index != len(scan_data_list):
            story.append(PageBreak())

    doc.build(story, onFirstPage=_draw_page_footer, onLaterPages=_draw_page_footer)
    return buffer.getvalue()
