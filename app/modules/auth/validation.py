import re
from fastapi import HTTPException


def validate_name(name: str):
    if not isinstance(name, str):
        raise HTTPException(status_code=400, detail="Name must be a string.")
    if name.strip() == "":
        raise HTTPException(status_code=400, detail="Name cannot be empty or just spaces.")
    stripped = re.sub(r"[ '\-]", "", name)
    if len(stripped) < 2:
        raise HTTPException(status_code=400, detail="Name must have at least 2 letters (excluding spaces/hyphens/apostrophes).")
    if len(stripped) > 50:
        raise HTTPException(status_code=400, detail="Name must be at most 50 letters (excluding spaces/hyphens/apostrophes).")
    if name[0] in {" ", "-", "'"} or name[-1] in {" ", "-", "'"}:
        raise HTTPException(status_code=400, detail="Name cannot start or end with a space, hyphen, or apostrophe.")
    if "  " in name or "--" in name or "''" in name:
        raise HTTPException(status_code=400, detail="Name cannot contain consecutive spaces, hyphens, or apostrophes.")
    if not re.fullmatch(r"[A-Za-z](?:[A-Za-z]|[ '\-](?=[A-Za-z]))*[A-Za-z]", name):
        raise HTTPException(status_code=400, detail="Name may only contain letters, single spaces, single hyphens, or single apostrophes; no digits or other punctuation.")


def validate_email(email: str):
    if not isinstance(email, str):
        raise HTTPException(status_code=400, detail="Email must be a string.")
    if len(email) > 254:
        raise HTTPException(status_code=400, detail="Email must be at most 254 characters long.")
    if email.count("@") != 1:
        raise HTTPException(status_code=400, detail="Email must contain exactly one '@' symbol.")
    local, domain = email.split("@")
    if not local or not domain:
        raise HTTPException(status_code=400, detail="Email must have both a local part and a domain part.")
    if " " in email:
        raise HTTPException(status_code=400, detail="Email cannot contain spaces.")
    if not re.fullmatch(r"[A-Za-z0-9._%+\-]+", local):
        raise HTTPException(status_code=400, detail="Local part of email has invalid characters.")
    if local[0] == "." or local[-1] == ".":
        raise HTTPException(status_code=400, detail="Local part of email cannot start or end with a dot.")
    if ".." in local:
        raise HTTPException(status_code=400, detail="Local part of email cannot contain consecutive dots.")
    if domain != domain.lower():
        raise HTTPException(status_code=400, detail="Email domain must be lowercase (e.g., example.com).")
    if "." not in domain:
        raise HTTPException(status_code=400, detail="Email domain must contain a '.' (e.g., example.com).")
    labels = domain.split(".")
    label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?$")
    for lbl in labels:
        if not (1 <= len(lbl) <= 63):
            raise HTTPException(status_code=400, detail="Each domain label must be between 1 and 63 characters.")
        if not label_pattern.fullmatch(lbl):
            raise HTTPException(status_code=400, detail="Domain labels must use only lowercase letters, digits, or hyphens, and cannot start/end with a hyphen.")
    tld = labels[-1]
    if not re.fullmatch(r"[a-z]{2,24}", tld):
        raise HTTPException(status_code=400, detail="Top-level domain must be 2–24 lowercase letters.")


def validate_password(password: str):
    if not isinstance(password, str):
        raise HTTPException(status_code=400, detail="Password must be a string.")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long.")
    if " " in password:
        raise HTTPException(status_code=400, detail="Password cannot contain spaces.")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one lowercase letter.")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one uppercase letter.")
    if not re.search(r"\d", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character (e.g., @, #, !, etc).")
