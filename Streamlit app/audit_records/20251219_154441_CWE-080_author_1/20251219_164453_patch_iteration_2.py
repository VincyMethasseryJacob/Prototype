from flask import render_template, request, escape

@app.route("/renderHtml")
def renderHTML():
    name = request.args.get("name", "World")
    safe_name = escape(name)
    return render_template("greeting.html", name=safe_name)
```

```html
<html><body><h1>Hello {{ name|safe }}</h1></body></html>