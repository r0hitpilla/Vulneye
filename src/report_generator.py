from jinja2 import Template

HTML_TMPL = """
<html>
  <head><title>VulnEye Report</title></head>
  <body>
    <h1>VulnEye Report</h1>
    {% for m in matches %}
      <div style="border:1px solid #ddd;padding:8px;margin:8px;">
        <h3>{{ m.asset.name }} - matched CVE</h3>
        <pre>{{ m.cve }}</pre>
      </div>
    {% endfor %}
  </body>
</html>
"""

def generate_html_report(matches, output_path):
    tmpl = Template(HTML_TMPL)
    rendered = tmpl.render(matches=matches)
    with open(output_path, 'w') as f:
        f.write(rendered)
