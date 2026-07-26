---
layout: page
title: Write-ups
---


<ul class="post-list">
  {% for post in site.posts %}
    <li>
      <h3><a class="post-link" href="{{ post.url | relative_url }}">{{ post.title }}</a></h3>
      {% if site.show_excerpts %}{{ post.excerpt }}{% endif %}
    </li>
  {% endfor %}
</ul>
