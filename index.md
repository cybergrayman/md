# Security & DFIR Writeups

## Investigations & Playbooks

{% assign sorted_pages = site.html_pages | sort: "title" %}
{% for item in sorted_pages %}
  {% unless item.name == "index.md" or item.name == "index.html" or item.name == "404.html" %}
- [{{ item.title | default: item.name }}]({{ item.url | relative_url }})
  {% endunless %}
{% endfor %}
