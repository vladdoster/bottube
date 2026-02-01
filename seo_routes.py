
# ---------------------------------------------------------------------------
# SEO & Crawler Support
# ---------------------------------------------------------------------------

@app.route("/robots.txt")
def robots_txt():
    """Serve robots.txt for search engine crawlers."""
    content = "User-agent: *\nAllow: /\nAllow: /watch/\nAllow: /agent/\nAllow: /agents\nAllow: /search\nDisallow: /api/\nDisallow: /login\nDisallow: /signup\nDisallow: /logout\n\nSitemap: https://bottube.ai/sitemap.xml\n"
    return app.response_class(content, mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap_xml():
    """Dynamic sitemap for search engines."""
    from datetime import datetime as _dt, timezone as _tz
    db = get_db()
    videos = db.execute(
        "SELECT video_id, created_at FROM videos ORDER BY created_at DESC LIMIT 1000"
    ).fetchall()
    agents = db.execute(
        "SELECT agent_name, created_at FROM agents ORDER BY created_at DESC"
    ).fetchall()

    lines = []
    lines.append('<?xml version="1.0" encoding="UTF-8"?>')
    lines.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')
    lines.append("  <url><loc>https://bottube.ai/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>")
    lines.append("  <url><loc>https://bottube.ai/agents</loc><changefreq>daily</changefreq><priority>0.8</priority></url>")
    lines.append("  <url><loc>https://bottube.ai/search</loc><changefreq>weekly</changefreq><priority>0.5</priority></url>")

    for v in videos:
        ts = _dt.fromtimestamp(float(v["created_at"]), tz=_tz.utc).strftime("%Y-%m-%d")
        lines.append("  <url><loc>https://bottube.ai/watch/" + v["video_id"] + "</loc><lastmod>" + ts + "</lastmod><priority>0.7</priority></url>")

    for a in agents:
        lines.append("  <url><loc>https://bottube.ai/agent/" + a["agent_name"] + "</loc><priority>0.6</priority></url>")

    lines.append("</urlset>")
    return app.response_class("\n".join(lines), mimetype="application/xml")


@app.route("/oembed")
def oembed():
    """oEmbed endpoint for rich link previews."""
    import re as _re
    url = request.args.get("url", "")
    fmt = request.args.get("format", "json")

    m = _re.search(r"/watch/([A-Za-z0-9_-]+)", url)
    if not m:
        return jsonify({"error": "Invalid URL"}), 404

    video_id = m.group(1)
    db = get_db()
    video = db.execute(
        "SELECT v.*, a.agent_name, a.display_name FROM videos v JOIN agents a ON v.agent_id = a.id WHERE v.video_id = ?",
        (video_id,)
    ).fetchone()

    if not video:
        return jsonify({"error": "Video not found"}), 404

    thumb_url = ""
    if video["thumbnail"]:
        thumb_url = "https://bottube.ai/thumbnails/" + video["thumbnail"]

    w = video["width"] or 512
    h = video["height"] or 512
    data = {
        "version": "1.0",
        "type": "video",
        "title": video["title"],
        "author_name": video["display_name"] or video["agent_name"],
        "author_url": "https://bottube.ai/agent/" + video["agent_name"],
        "provider_name": "BoTTube",
        "provider_url": "https://bottube.ai",
        "thumbnail_url": thumb_url,
        "html": '<iframe src="https://bottube.ai/embed/' + video_id + '" width="' + str(w) + '" height="' + str(h) + '" frameborder="0" allowfullscreen></iframe>',
        "width": w,
        "height": h,
    }

    if fmt == "xml":
        xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>', "<oembed>"]
        for k, val in data.items():
            xml_parts.append("<" + k + ">" + str(val) + "</" + k + ">")
        xml_parts.append("</oembed>")
        return app.response_class("\n".join(xml_parts), mimetype="text/xml")

    return jsonify(data)
