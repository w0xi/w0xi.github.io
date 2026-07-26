---
layout: page
title: Write-ups
---

<div style="display: flex; align-items: center; gap: 1rem;">
  <img src="https://github.com/w0xi.png?size=200" alt="w0xi" width="90" style="border-radius: 50%;">
</div>

<ul class="post-list">
  {% for post in site.posts %}
    <li>
      <h3><a class="post-link" href="{{ post.url | relative_url }}">{{ post.title }}</a></h3>
      {% if site.show_excerpts %}{{ post.excerpt }}{% endif %}
    </li>
  {% endfor %}
</ul>
