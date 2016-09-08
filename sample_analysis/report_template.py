# Not a django template.
# This is used for generating the plaintext report ("Plaintext" tab in output)

report_template = """\
{{ %(sample.ticket)s }}, Analysis Complete, Non-Incident
{{ %(sample.ticket)s }}, Analysis Complete, SPAM
{{ %(sample.ticket)s }}, Analysis Complete, AV-Detected
{{ %(sample.ticket)s }}, Analysis Complete, Malcode Detected

Reason for Ticket/Alert         :

{% if ta_domains %}DNS Callout                     :    {% for domain in ta_domains %}{{ domain }}  {% endfor %}{% endif %}
{% if ta_ips %}IP Callout                      :    {% for ip in ta_ips %}{{ ip }}  {% endfor %}{% endif %}

File                            :    {{ sample.filename }}
MD5                             :    {{ sample.md5 }}
SHA1                            :    {{ sample.sha1 }}
SHA256                          :    {{ sample.sha256 }}
FUZZY                           :    {{ sample.fuzzy }}
Size                            :    {{ sample.size }}
Path                            :
Type                            :    {{ filetype }}
Analyzed Date/Time              :    {{ sample.created }}

CVE                             :

Link(s)                         :

Caught by AV (YES/NO)           :    {% if plaintext.vt_short %}YES{% endif %}
                      VT        :    {% if plaintext.vt_nums %}{{ plaintext.vt_nums }}{% endif %}
                      {% if plaintext.vt_short %}{% for res in plaintext.vt_short %}{{ res.vendor }}{{ res.detect }}
                      {% endfor %}{% endif %}

Email Info                      :

--SUMMARY--



--REMEDIATION STEPS--

- False Positive

- Block the following:
        Block:
        Justification:
        
- Search for successful callouts

- Follow malicious email remediation procedures

- Operational/Approved activity

- Close ticket


--NOTES--

{% if virustotal %}#### VirusTotal ####
{{ virustotal }}{% endif %}

#### EXIF Data ####
{{ exif }}

#### TRiD ####
{{ trid }}

{% if s.peframe %}#### PEFRAME ####
{{ peframe }}{% endif %}

{% if s.pescanner %}#### PEScanner ####
{{ pescanner }}{% endif %}

{% if s.pdfid %}#### PDFiD ####
{{ pdfid }}{% endif %}

{% if s.peepdf %}#### PEEPDF ####
{{ peepdf }}{% endif %}

{% if s.pdf_strings %} #### PDF Strings ####
{{ pdfstrings }}{% endif %}

{% if s.oleid %}#### OLEID ####
{{ oleid }}{% endif %}

{% if s.olemeta %}#### OLEMeta ####
{{ olemeta }}{% endif %}

{% if s.olevba %}#### OLEVBA ####
{{ olevba }}{% endif %}

{% if s.rtfobj %}#### RTFOBJ ####
{{ rtfobj }}{% endif %}

#### Balbuzard ####
{{ balbuzard }}

#### Strings ####
{{ strings }}"""
