import os
import sys
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import parse_xml, OxmlElement
from docx.oxml.ns import nsdecls, qn

def create_report(output_path):
    doc = Document()

    # Set page margins (1 inch)
    sections = doc.sections
    for section in sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Palette
    COLOR_PRIMARY = RGBColor(26, 54, 93)     # Deep Navy #1A365D
    COLOR_SECONDARY = RGBColor(43, 108, 176) # Indigo Blue #2B6CB0
    COLOR_DARK = RGBColor(45, 55, 72)        # Slate Dark #2D3748
    COLOR_MUTED = RGBColor(113, 128, 150)    # Slate Muted #718096
    COLOR_DANGER = RGBColor(197, 48, 48)     # Crimson Rose #C53030

    HEX_PRIMARY = "1A365D"
    HEX_SECONDARY = "2B6CB0"
    HEX_LIGHT_BG = "F7FAFC"
    HEX_BORDER = "E2E8F0"
    HEX_CALLOUT_BG = "EDF2F7"

    def set_cell_background(cell, hex_color):
        shading_xml = f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>'
        cell._tc.get_or_add_tcPr().append(parse_xml(shading_xml))

    def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
        tcPr = cell._tc.get_or_add_tcPr()
        tcMar = OxmlElement('w:tcMar')
        for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
            node = OxmlElement(f'w:{m}')
            node.set(qn('w:w'), str(val))
            node.set(qn('w:type'), 'dxa')
            tcMar.append(node)
        tcPr.append(tcMar)

    def add_callout(text, prefix="SECURITY POLICY NOTE:"):
        table = doc.add_table(rows=1, cols=1)
        table.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = table.cell(0, 0)
        set_cell_background(cell, HEX_CALLOUT_BG)
        set_cell_margins(cell, top=140, bottom=140, left=200, right=200)
        
        # Left border highlight
        tcPr = cell._tc.get_or_add_tcPr()
        borders = parse_xml(f'<w:tcBorders {nsdecls("w")}><w:left w:val="single" w:sz="24" w:space="0" w:color="{HEX_PRIMARY}"/><w:top w:val="none"/><w:right w:val="none"/><w:bottom w:val="none"/></w:tcBorders>')
        tcPr.append(borders)
        
        p = cell.paragraphs[0]
        p.paragraph_format.space_before = Pt(2)
        p.paragraph_format.space_after = Pt(2)
        run_pre = p.add_run(f"{prefix} ")
        run_pre.bold = True
        run_pre.font.size = Pt(10)
        run_pre.font.color.rgb = COLOR_PRIMARY
        
        run_body = p.add_run(text)
        run_body.font.size = Pt(9.5)
        run_body.font.color.rgb = COLOR_DARK
        doc.add_paragraph() # Spacing

    # -------------------------------------------------------------
    # DOCUMENT HEADER / TITLE
    # -------------------------------------------------------------
    p_title = doc.add_paragraph()
    p_title.paragraph_format.space_before = Pt(0)
    p_title.paragraph_format.space_after = Pt(4)
    run_title = p_title.add_run("TrustGuard: Dynamic Zero Trust Access Control")
    run_title.font.name = "Calibri"
    run_title.font.size = Pt(24)
    run_title.bold = True
    run_title.font.color.rgb = COLOR_PRIMARY

    p_sub = doc.add_paragraph()
    p_sub.paragraph_format.space_before = Pt(0)
    p_sub.paragraph_format.space_after = Pt(14)
    run_sub = p_sub.add_run("Comprehensive System Features Specification & Mathematical Trust Score Formulation")
    run_sub.font.name = "Calibri"
    run_sub.font.size = Pt(13)
    run_sub.font.color.rgb = COLOR_SECONDARY

    # Metadata Banner
    p_meta = doc.add_paragraph()
    p_meta.paragraph_format.space_before = Pt(0)
    p_meta.paragraph_format.space_after = Pt(20)
    run_meta = p_meta.add_run("Domain: Land Records & Revenue Administration (Tamil Nadu LRIS)  |  Architecture: Zero Trust PDP/PEP")
    run_meta.font.size = Pt(9)
    run_meta.font.color.rgb = COLOR_MUTED
    run_meta.italic = True

    # Horizontal Divider Line
    p_div = doc.add_paragraph()
    p_div.paragraph_format.space_after = Pt(14)
    r_div = p_div.add_run("―" * 58)
    r_div.font.color.rgb = COLOR_MUTED

    # -------------------------------------------------------------
    # SECTION 1: ARCHITECTURAL FOUNDATION & EXECUTIVE SUMMARY
    # -------------------------------------------------------------
    h1 = doc.add_heading("1. Architectural Foundation & Executive Summary", level=1)
    h1.style.font.color.rgb = COLOR_PRIMARY

    p1 = doc.add_paragraph(
        "TrustGuard is a specialized Dynamic Zero Trust Access Control framework designed for high-security, "
        "sensitive public infrastructure—specifically the digitised land deeds and Record of Rights (ROR) of "
        "the Government of Tamil Nadu. Traditional perimeter-based authentication relies on granting persistent "
        "access tokens that remain valid regardless of environmental or behavioral changes. In contrast, TrustGuard "
        "treats every request as an unauthenticated event that must be continuously evaluated across administrative "
        "jurisdictions, device integrity, network routes, temporal boundaries, and machine learning behavioral patterns."
    )
    p1.style.font.size = Pt(10.5)

    p2 = doc.add_paragraph(
        "The system decouples policy decision from request handling through a centralized Policy Decision Point (PDP) "
        "and Policy Enforcement Point (PEP) model. Before any data payload, database row, certified document extract, "
        "or signed URL is returned to the client, the backend authenticates the identity, inspects jurisdictional scope, "
        "evaluates the rule-based threat engine, runs the Scikit-Learn Isolation Forest anomaly model, and derives "
        "a composite Explainable Trust Score."
    )
    p2.style.font.size = Pt(10.5)

    add_callout(
        "Core Zero Trust Axiom: \"Never Trust, Always Verify, Continuously Re-evaluate.\" "
        "A user who logs in with a high trust score cannot bypass jurisdictional boundaries or maintain access "
        "if suspicious route shifts or behavioral spikes are detected.",
        "FUNDAMENTAL DESIGN PRINCIPLE:"
    )

    # -------------------------------------------------------------
    # SECTION 2: EXHAUSTIVE CATALOGUE OF SYSTEM FEATURES
    # -------------------------------------------------------------
    h2 = doc.add_heading("2. Exhaustive Catalogue of Project Features", level=1)
    h2.style.font.color.rgb = COLOR_PRIMARY

    features = [
        ("Feature 1: Zero Trust Gateway & Authentication", [
            ("Multi-Factor Credential Engine", "Bcrypt-hashed credential validation with SHA-256 password salt verification."),
            ("Cryptographic JWT Minting", "Issues cryptographically signed JSON Web Tokens encoding user ID, email, administrative role, and authorized jurisdiction coordinates."),
            ("Device Fingerprint Registration", "Extracts browser hardware headers, client user-agents, OS versions, and screen resolutions to establish an immutable authorized hardware baseline."),
            ("Concurrent Session Interception", "Detects simultaneous logins across different machines or IP routes under the same User ID, immediately degrading trust score and enforcing a Step-Up challenge."),
            ("Session Teardown & Invalidation", "Clean session destruction on logout, clearing in-memory registries, revoking JWT integrity, and logging forensic teardown timestamps.")
        ]),
        ("Feature 2: Real-Time Off-Hours Night Access Detection & Blocking", [
            ("IST Timezone Enforcement", "Evaluates all requests strictly in Indian Standard Time (Asia/Kolkata), independent of host system or cloud runtime timezone (e.g. UTC on Render)."),
            ("Working Hours Policy", "Permitted window: 07:00:00 AM to 06:59:59 PM IST. Restricted window: 07:00:00 PM (19:00:00) to 06:59:59 AM (< 07:00:00) IST."),
            ("Pre-Authentication Rejection", "Off-hours login attempts are blocked immediately before issuing any session token or JWT. Returns HTTP 403 Forbidden with security status 'ACCESS BLOCKED'."),
            ("Forensic Warning Notice", "Displays actual IST timestamp, incident classification 'Off-Hours Night Access', and operating hours policy notice on the login screen."),
            ("10-Point Rule Penalty", "Applies an immediate 10-point rule risk penalty (O=1), generates a SIEM alert, and logs an audit trail event even though authentication was denied."),
            ("Universal Multi-Role Enforcement", "Enforced equally on Admin, Tahsildar, Deputy Tahsildar, Revenue Inspector, VAO, DEO, and Citizen without exception.")
        ]),
        ("Feature 3: Pre-Access Cross-Jurisdiction Authorization (PDP & PEP)", [
            ("Administrative Hierarchy Mapping", "Enforces strict revenue hierarchy: District -> Taluk -> Village. Access is denied if the user lacks jurisdiction over the requested record."),
            ("Village Administrative Officer (VAO) Scope", "Restricted strictly to the assigned village (e.g., Mudichur / v1). Attempting access to a neighboring village in the same taluk is strictly blocked."),
            ("Revenue Inspector (RI) Scope", "Authorized across all villages within their assigned taluk (e.g., Tambaram). Out-of-taluk records are blocked."),
            ("Tahsildar & Deputy Tahsildar Scope", "Administrative authority across the entire revenue division / taluk."),
            ("Citizen Ownership Isolation", "Citizens can only inspect land parcels where they are the verified legal owner. Other parcels in the same village trigger access denial and a 10-point penalty."),
            ("Separation of Duties (SoD)", "System Administrators are barred from viewing private land deeds or modifying database records, preventing administrative insider threats."),
            ("Pre-Payload Data Redaction", "Access checks run on the backend before data payloads or URLs are sent. Document details and download buttons remain locked and return HTTP 403.")
        ]),
        ("Feature 4: Certified Land Office Schedules (Dynamic Document Generation)", [
            ("e-Patta Passbook Extract", "Generates official Government of Tamil Nadu e-Patta extracts with parcel extent, survey/sub-division numbers, owner name, patta number, and revenue digital seal."),
            ("Chitta Land Register Extract", "Dynamic extract of Department of Revenue & Disaster Management land registers, featuring wet/dry land tax assessments and fasli year records."),
            ("Field Measurement Book (FMB) Copy", "Survey & Settlement Directorate FMB copies detailing ladder measurements, traverse coordinate lines, azimuths, and boundary parcel marks."),
            ("Dynamic Streaming Downloads", "Direct file downloads streaming dynamic certified .txt extracts with authentic Content-Disposition headers, gated by real-time jurisdiction checks.")
        ]),
        ("Feature 5: Multi-Tier Land Mutation Progression Engine", [
            ("5-Stage Approval Pipeline", "Progresses through: Application Submitted -> Pending VAO -> Pending RI -> Pending Deputy Tahsildar -> Pending Tahsildar -> Approved/Rejected."),
            ("Role-Progression Enforcement", "Only the officer assigned to the current mutation status can verify and advance the application."),
            ("Trust Score Gating", "Officers must possess a trust score >= 60 to perform mutation verifications. Approvals at lower scores are blocked."),
            ("Immutable Ownership Transfer", "Upon final Tahsildar approval, the land record row is updated with new ownership and an immutable SHA-256 audit hash.")
        ]),
        ("Feature 6: Interactive Threat Simulator & Telemetry Injector", [
            ("6 Core Threat Vectors", "Simulates: Device Mismatch (20 pts), IP Route Drift (20 pts), Cross-Jurisdiction (20 pts), Off-Hours (10 pts), Rapid Request Spike (20 pts), Post-Idle Burst (10 pts)."),
            ("Exact 100-Point Sum", "All 6 simulation vectors sum to exactly 100 points: 20 + 20 + 20 + 10 + 20 + 10 = 100."),
            ("Real-Time Telemetry Updates", "Instantly injects behavioral anomalies into active sessions, triggering real-time trust score degradation and UI posture transitions."),
            ("One-Click Posture Reset", "Clears active threat flags and recalculates clean baseline trust scores.")
        ]),
        ("Feature 7: Dual Email Engine & Cryptographic Step-Up OTP", [
            ("Resilient Email Dispatch", "Primary delivery via NodeMailer (Gmail SMTP) with automatic fallback to Brevo HTTPS API."),
            ("Dynamic OTP Challenge", "Automatically dispatched when session trust score drops to or below the configured role threshold."),
            ("Posture Restoration Bonus", "Successful 6-digit OTP verification adds a +20 point bonus and restores user capabilities from Restricted to Full Access.")
        ]),
        ("Feature 8: Forensic Audit Trail & SIEM Alert Manager", [
            ("Immutable Forensic Logging", "Captures user ID, role, client IP, device fingerprint, trust score before/after, decision, rule penalties, and timestamps."),
            ("SIEM Alert Lifecycle", "Categorizes security alerts with status tracking (NEW -> INVESTIGATING -> RESOLVED)."),
            ("10-Minute Cooldown Deduplication", "Suppresses duplicate alert spam while preserving forensic log entries.")
        ]),
        ("Feature 9: Security Analytics & Visual Dashboard", [
            ("Incidents by Category", "Real-time bar counters tracking Off-Hours Access, IP Drift, Device Mismatch, Velocity Violations, and Jurisdiction Bypasses."),
            ("Trust Score Distribution", "Histogram tracking sessions in 0-25, 26-50, 51-75, and 76-100 score bands."),
            ("Top Accessed Document Telemetry", "Identifies frequently viewed survey parcels to prevent mass scraping.")
        ]),
        ("Feature 10: Role-Based Access Control & User Administration", [
            ("User Profile Management", "Enables administrators to view active users, assign administrative jurisdictions, and update credentials."),
            ("Active Session Monitor", "Displays real-time telemetry for all concurrent sessions with instant remote termination capability.")
        ])
    ]

    for title, items in features:
        h3 = doc.add_heading(title, level=2)
        h3.style.font.color.rgb = COLOR_SECONDARY
        for sub_title, desc in items:
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.space_after = Pt(3)
            r_bold = p.add_run(f"• {sub_title}: ")
            r_bold.bold = True
            r_bold.font.size = Pt(10)
            r_bold.font.color.rgb = COLOR_DARK
            r_desc = p.add_run(desc)
            r_desc.font.size = Pt(9.5)
            r_desc.font.color.rgb = COLOR_DARK

    # -------------------------------------------------------------
    # SECTION 3: MATHEMATICAL TRUST SCORE FORMULATION
    # -------------------------------------------------------------
    h3_sec = doc.add_heading("3. Mathematical Trust Score Formulation & Architecture", level=1)
    h3_sec.style.font.color.rgb = COLOR_PRIMARY

    p_form_intro = doc.add_paragraph(
        "TrustGuard calculates trust using an explainable, deterministic hybrid model combining a Rule-Based Threat Engine "
        "and a Machine Learning Isolation Forest Anomaly Detection Service. The initial trust score begins at a clean "
        "baseline of 100 points and degrades proportionally only upon verifiable threat evidence."
    )
    p_form_intro.style.font.size = Pt(10)

    # Master Formula Box
    add_callout(
        "FinalTrustScore = max( 0, min( 100, round( 100 - RuleRisk - MLRisk + OTPBonus ) ) )\n\n"
        "Where:\n"
        "• RuleRisk = 20(D) + 20(I) + 20(J) + 10(O) + 20(R) + 10(P) + 10(F)\n"
        "• MLRisk = min( 25, round( NAS * 25 ) ) when NAS >= 0.50 (else 0)\n"
        "• OTPBonus = +20 points upon successful 6-digit email identity verification\n"
        "• Maximum Rule Risk = 100 points  |  Minimum Trust Score = 0 points",
        "MASTER HYBRID TRUST SCORE FORMULA:"
    )

    # Table of Rule Engine Factors
    h4_table = doc.add_heading("3.1 Rule-Based Threat Penalty Weights", level=2)
    h4_table.style.font.color.rgb = COLOR_SECONDARY

    rule_table = doc.add_table(rows=1, cols=4)
    rule_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_cells = rule_table.rows[0].cells
    headers = ["Factor Code", "Security Threat Signal", "Penalty Weight", "Trigger Condition"]
    for i, title in enumerate(headers):
        hdr_cells[i].text = title
        set_cell_background(hdr_cells[i], HEX_PRIMARY)
        hdr_cells[i].paragraphs[0].runs[0].font.bold = True
        hdr_cells[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
        hdr_cells[i].paragraphs[0].runs[0].font.size = Pt(9.5)

    rule_data = [
        ("D", "Device Fingerprint Mismatch", "-20 points", "Client hardware/browser hash differs from registered workstation."),
        ("I", "Mid-Session IP Route Drift", "-20 points", "Client IP address shifts unexpectedly mid-session or uses VPN proxy."),
        ("J", "Cross-Jurisdiction Access Attempt", "-20 points", "Officer attempts to view/download parcel outside assigned village/taluk."),
        ("O", "Off-Hours Night Access", "-10 points", "Access attempt occurs between 7:00 PM and 7:00 AM IST (Asia/Kolkata)."),
        ("R", "Rapid Request Spike Attack", "-20 points", "Velocity anomaly exceeding allowable rate limits (>25 requests/min)."),
        ("P", "Post-Idle Burst Anomaly", "-10 points", "Burst of high-impact mutations triggered after >30 minutes of inactivity."),
        ("F", "Failed Operation Count", "-10 points / attempt", "Repeated unauthorized inspection attempts or access policy violations."),
        ("B", "Step-Up OTP Restoration Bonus", "+20 points", "Awarded upon successful 6-digit cryptographic email OTP verification.")
    ]

    for row_data in rule_data:
        row_cells = rule_table.add_row().cells
        for col_idx, text in enumerate(row_data):
            row_cells[col_idx].text = text
            set_cell_margins(row_cells[col_idx], top=60, bottom=60, left=100, right=100)
            p = row_cells[col_idx].paragraphs[0]
            p.runs[0].font.size = Pt(9)
            p.runs[0].font.color.rgb = COLOR_DARK
            if col_idx == 0:
                p.runs[0].font.bold = True
                p.runs[0].font.color.rgb = COLOR_SECONDARY
            elif col_idx == 2:
                p.runs[0].font.bold = True
                if "+" in text:
                    p.runs[0].font.color.rgb = RGBColor(40, 167, 69)
                else:
                    p.runs[0].font.color.rgb = COLOR_DANGER

    # 3.2 Machine Learning Model
    h4_ml = doc.add_heading("3.2 Scikit-Learn Isolation Forest Anomaly Detection", level=2)
    h4_ml.style.font.color.rgb = COLOR_SECONDARY

    p_ml = doc.add_paragraph(
        "TrustGuard deploys a high-fidelity Scikit-Learn Isolation Forest model that continuously monitors session behavior. "
        "The model analyzes a 7-dimensional behavioral telemetry vector:\n"
        "1. requests_per_minute (Normal baseline: 1.8 to 14.2 req/min)\n"
        "2. records_viewed (Normal baseline: 1 to 20 records)\n"
        "3. downloads_count (Normal baseline: 0 to 5 extracts)\n"
        "4. failed_operations (Normal baseline: 0 to 3 attempts)\n"
        "5. login_hour (Normal baseline: 07:00 to 19:00 IST)\n"
        "6. session_duration_minutes (Normal baseline: 5 to 118 minutes)\n"
        "7. document_sensitivity (Classification index: Public = 1, Confidential = 2, Restricted = 3)\n\n"
        "The model computes a Normalized Anomaly Score (NAS) between 0.0000 and 1.0000. When NAS >= 0.50, the session is "
        "classified as anomalous, generating a proportional ML penalty:\n"
        "MLRisk = min( 25, round( NAS * 25 ) )"
    )
    p_ml.style.font.size = Pt(9.5)

    # -------------------------------------------------------------
    # SECTION 4: SCENARIO-BY-SCENARIO TRUST SCORE WALKTHROUGH
    # -------------------------------------------------------------
    h4_sec = doc.add_heading("4. Scenario-by-Scenario Detailed Mathematical Calculations", level=1)
    h4_sec.style.font.color.rgb = COLOR_PRIMARY

    scenarios = [
        ("Scenario 1: Fresh Login on Registered Hardware during Working Hours",
         "User logs in from registered device (D=0), authorized IP (I=0), at 10:30 AM IST (O=0), no failed actions (F=0).",
         "RuleRisk = 20(0) + 20(0) + 20(0) + 10(0) + 20(0) + 10(0) = 0\n"
         "MLRisk = 0 (NAS = 0.015 < 0.50)\n"
         "FinalTrustScore = 100 - 0 - 0 = 100 / 100",
         "100 / 100", "FULL ACCESS (Low Risk - Green Tier)"),

        ("Scenario 2: Device Fingerprint Mismatch (Untrusted Hardware)",
         "User logs in from an unrecognized laptop with hardware mismatch (D=1).",
         "RuleRisk = 20(D=1) = 20 points\n"
         "MLRisk = 0\n"
         "FinalTrustScore = 100 - 20 = 80 / 100",
         "80 / 100", "FULL ACCESS (Low Risk - Score drops by 20 points)"),

        ("Scenario 3: Mid-Session IP Route Drift (VPN Proxy Shift)",
         "Active session experiences network route drift from 192.168.1.104 to 10.0.0.1 (I=1).",
         "RuleRisk = 20(I=1) = 20 points\n"
         "MLRisk = 0\n"
         "FinalTrustScore = 100 - 20 = 80 / 100",
         "80 / 100", "FULL ACCESS (Score drops by 20 points)"),

        ("Scenario 4: Device Mismatch + IP Drift Combined",
         "User connects from untrusted device (D=1) and anomalous IP address (I=1).",
         "RuleRisk = 20(D=1) + 20(I=1) = 40 points\n"
         "MLRisk = 0\n"
         "FinalTrustScore = 100 - 40 = 60 / 100",
         "60 / 100", "RESTRICTED (Medium Risk - Step-Up OTP Dispatched)"),

        ("Scenario 5: Cross-Jurisdiction Land Document Access Attempt",
         "VAO Anitha (Mudichur) attempts to open or view a record from Pillaipakkam (J=1).",
         "RuleRisk = 20(J=1) = 20 points\n"
         "Document contents and metadata are withheld before response.\n"
         "FinalTrustScore = 100 - 20 = 80 / 100 (or from 90 -> 70)",
         "70 - 80 / 100", "ACCESS DENIED (HTTP 403 Forbidden - Viewer Modal Closed)"),

        ("Scenario 6: Real-Time Off-Hours Night Access Attempt (07:00 PM - 07:00 AM IST)",
         "User attempts login at 08:45 PM IST (O=1). Current time is in restricted night window.",
         "RuleRisk = 10(O=1) = 10 points\n"
         "Authentication rejected before token issuance.\n"
         "FinalTrustScore = 100 - 10 = 90 / 100",
         "90 / 100", "ACCESS BLOCKED (HTTP 403 Forbidden - No Token Issued)"),

        ("Scenario 7: Rapid Request Velocity Spike (Automated Scraping Attack)",
         "Automated crawler triggers >25 requests/min (R=1). Behavioral NAS escalates to 0.68.",
         "RuleRisk = 20(R=1) = 20 points\n"
         "MLRisk = round(0.68 * 25) = 17 points\n"
         "FinalTrustScore = 100 - 20 - 17 = 63 / 100",
         "63 / 100", "RESTRICTED (Rate Limiter Throttle HTTP 429 Active)"),

        ("Scenario 8: Post-Idle Burst Anomaly",
         "Session idle for >30 minutes suddenly submits rapid mutations (P=1).",
         "RuleRisk = 10(P=1) = 10 points\n"
         "FinalTrustScore = 100 - 10 = 90 / 100",
         "90 / 100", "FULL ACCESS (Logged in Telemetry Monitor)"),

        ("Scenario 9: Repeated Unauthorized Operations / Authorization Failures",
         "User makes 3 unauthorized access attempts to restricted records (F=3).",
         "RuleRisk = 3 * 10 = 30 points\n"
         "FinalTrustScore = 100 - 30 = 70 / 100",
         "70 / 100", "RESTRICTED (Sensitive Workflows Locked)"),

        ("Scenario 10: Step-Up OTP Verification & Posture Recovery",
         "Session score at 60 (Restricted). User successfully verifies 6-digit email OTP.",
         "OTPBonus = +20 points\n"
         "FinalTrustScore = min(100, 60 + 20) = 80 / 100",
         "80 / 100", "FULL ACCESS (Restoration Bonus Applied - Unlocked)"),

        ("Scenario 11: Cumulative Threat Simulator (All 6 Vectors Active)",
         "Threat Simulator activates all 6 threats: D=1, I=1, J=1, O=1, R=1, P=1.",
         "RuleRisk = 20(D) + 20(I) + 20(J) + 10(O) + 20(R) + 10(P) = 100 points\n"
         "RuleTrust = max(0, 100 - 100) = 0\n"
         "FinalTrustScore = max(0, 100 - 100 - MLRisk) = 0 / 100",
         "0 / 100", "BLOCKED / TERMINATED (Critical Risk - Session Locked)")
    ]

    for title, condition, calc, score, outcome in scenarios:
        p_sc = doc.add_paragraph()
        p_sc.paragraph_format.space_before = Pt(8)
        p_sc.paragraph_format.space_after = Pt(2)
        r_sc_t = p_sc.add_run(f"• {title}")
        r_sc_t.bold = True
        r_sc_t.font.size = Pt(10.5)
        r_sc_t.font.color.rgb = COLOR_SECONDARY

        sc_table = doc.add_table(rows=4, cols=2)
        sc_table.alignment = WD_TABLE_ALIGNMENT.CENTER
        sc_data = [
            ("Conditions / Threat Signals:", condition),
            ("Mathematical Formulation:", calc),
            ("Resulting Trust Score:", score),
            ("Policy Decision & PEP Outcome:", outcome)
        ]
        for r_idx, (lbl, val) in enumerate(sc_data):
            c0, c1 = sc_table.rows[r_idx].cells
            c0.width = Inches(2.2)
            c1.width = Inches(4.3)
            c0.text = lbl
            c1.text = val
            set_cell_background(c0, HEX_LIGHT_BG)
            set_cell_margins(c0, top=40, bottom=40, left=80, right=80)
            set_cell_margins(c1, top=40, bottom=40, left=80, right=80)
            c0.paragraphs[0].runs[0].font.bold = True
            c0.paragraphs[0].runs[0].font.size = Pt(8.5)
            c0.paragraphs[0].runs[0].font.color.rgb = COLOR_MUTED
            c1.paragraphs[0].runs[0].font.size = Pt(8.5)
            c1.paragraphs[0].runs[0].font.color.rgb = COLOR_DARK
            if r_idx == 2:
                c1.paragraphs[0].runs[0].font.bold = True
                c1.paragraphs[0].runs[0].font.color.rgb = COLOR_PRIMARY
            elif r_idx == 3:
                c1.paragraphs[0].runs[0].font.bold = True
                if "BLOCKED" in val or "DENIED" in val or "TERMINATED" in val:
                    c1.paragraphs[0].runs[0].font.color.rgb = COLOR_DANGER
                elif "RESTRICTED" in val:
                    c1.paragraphs[0].runs[0].font.color.rgb = RGBColor(214, 158, 46)
                else:
                    c1.paragraphs[0].runs[0].font.color.rgb = RGBColor(40, 167, 69)

    # -------------------------------------------------------------
    # SECTION 5: POLICY DECISION & THRESHOLD MATRICES
    # -------------------------------------------------------------
    h5 = doc.add_heading("5. Access Decision & Threshold Policy Matrices", level=1)
    h5.style.font.color.rgb = COLOR_PRIMARY

    p_pol_intro = doc.add_paragraph(
        "The dynamic trust score directly governs the user's operational capabilities across the application. "
        "The system enforces four distinct access modes and role-specific OTP step-up challenge thresholds:"
    )
    p_pol_intro.style.font.size = Pt(10)

    # Policy Table
    pol_table = doc.add_table(rows=1, cols=4)
    pol_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_p = pol_table.rows[0].cells
    for i, t in enumerate(["Score Range", "Risk Level", "Policy Decision", "Operational Permissions"]):
        hdr_p[i].text = t
        set_cell_background(hdr_p[i], HEX_PRIMARY)
        hdr_p[i].paragraphs[0].runs[0].font.bold = True
        hdr_p[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
        hdr_p[i].paragraphs[0].runs[0].font.size = Pt(9.5)

    pol_rows = [
        ("80 - 100", "LOW RISK", "FULL ACCESS", "Full read/write/mutate capabilities. Unrestricted document viewing and downloading. No OTP challenges."),
        ("60 - 79", "MEDIUM RISK", "RESTRICTED", "Authorized document extracts accessible. Mutation approvals require Step-Up OTP. Download rate limited."),
        ("40 - 59", "HIGH RISK", "READ-ONLY", "Metadata view only. Certified downloads and mutation creation/approvals locked. Step-Up OTP challenge active."),
        ("0 - 39", "CRITICAL RISK", "BLOCKED / TERMINATED", "Access revoked immediately. Session locked out. Gateway blocks all requests until full identity verification.")
    ]

    for p_data in pol_rows:
        r_c = pol_table.add_row().cells
        for idx, text in enumerate(p_data):
            r_c[idx].text = text
            set_cell_margins(r_c[idx], top=60, bottom=60, left=100, right=100)
            p = r_c[idx].paragraphs[0]
            p.runs[0].font.size = Pt(9)
            p.runs[0].font.color.rgb = COLOR_DARK
            if idx == 0:
                p.runs[0].font.bold = True
            elif idx == 2:
                p.runs[0].font.bold = True
                if "FULL" in text:
                    p.runs[0].font.color.rgb = RGBColor(40, 167, 69)
                elif "RESTRICTED" in text:
                    p.runs[0].font.color.rgb = RGBColor(214, 158, 46)
                elif "BLOCKED" in text:
                    p.runs[0].font.color.rgb = COLOR_DANGER

    # Role Thresholds Table
    h5_role = doc.add_heading("5.1 Role-Specific Step-Up Challenge Thresholds", level=2)
    h5_role.style.font.color.rgb = COLOR_SECONDARY

    role_table = doc.add_table(rows=1, cols=3)
    role_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hdr_r = role_table.rows[0].cells
    for i, t in enumerate(["Administrative Role", "Jurisdictional Scope", "Step-Up OTP Challenge Trigger"]):
        hdr_r[i].text = t
        set_cell_background(hdr_r[i], HEX_SECONDARY)
        hdr_r[i].paragraphs[0].runs[0].font.bold = True
        hdr_r[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
        hdr_r[i].paragraphs[0].runs[0].font.size = Pt(9.5)

    role_rows = [
        ("System Administrator", "Global System (Barred from land record rows under SoD)", "Trust Score <= 60 points"),
        ("Tahsildar", "Entire Taluk / Revenue Division (Final Mutation Adjudicator)", "Trust Score <= 60 points"),
        ("Deputy Tahsildar", "Assigned Sub-Division / Taluk (Revenue Scrutiny Officer)", "Trust Score <= 60 points"),
        ("Revenue Inspector (RI)", "Assigned Firka / Taluk (Field Verification Officer)", "Trust Score <= 55 points"),
        ("Village Administrative Officer (VAO)", "Assigned Village (Mudichur / v1)", "Trust Score <= 60 points"),
        ("Data Entry Operator (DEO)", "Assigned Village Data Entry Desk", "Trust Score <= 50 points"),
        ("Citizen", "Registered Personal Land Parcels Only", "Trust Score <= 40 points")
    ]

    for r_data in role_rows:
        r_cells = role_table.add_row().cells
        for idx, text in enumerate(r_data):
            r_cells[idx].text = text
            set_cell_margins(r_cells[idx], top=50, bottom=50, left=90, right=90)
            p = r_cells[idx].paragraphs[0]
            p.runs[0].font.size = Pt(9)
            p.runs[0].font.color.rgb = COLOR_DARK
            if idx == 0:
                p.runs[0].font.bold = True
            elif idx == 2:
                p.runs[0].font.bold = True
                p.runs[0].font.color.rgb = COLOR_PRIMARY

    # Save document
    doc.save(output_path)
    print(f"Report successfully saved to {output_path}")

if __name__ == "__main__":
    out_dir = r"c:\Users\svkow\Downloads\Project1"
    out_file = os.path.join(out_dir, "TrustGuard_Complete_Features_and_Trust_Score_Report.docx")
    create_report(out_file)
