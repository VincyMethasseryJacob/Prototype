from flask import render_template_string, request, make_response

@app.route("/renderHtml")
def renderHTML():
    name = request.args.get("name", "World")
    html_content = "<html><body><h1>Hello {{ name }}</h1></body></html>"
    response = make_response(render_template_string(html_content, name=name))
    response.headers["Content-Type"] = "text/html"
    return response