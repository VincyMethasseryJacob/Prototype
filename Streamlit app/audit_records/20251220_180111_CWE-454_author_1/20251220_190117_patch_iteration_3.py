def admin_access(request):
    global HAS_ADMIN_ACCESS
    username = request.get("username")
    password = request.get("password")
    if username == "admin" and password == "admin123":
        HAS_ADMIN_ACCESS = True
    else:
        HAS_ADMIN_ACCESS = False