import os
import re
import uvicorn
import json
from fastapi import FastAPI, Request, Response, status, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional
from pydantic import BaseModel
from deta import Deta
from dotenv import load_dotenv
from datetime import datetime
import requests


load_dotenv()
DETA_TOKEN = os.getenv("DETA_TOKEN")

app = FastAPI()
deta = Deta(DETA_TOKEN)
templates = Jinja2Templates(directory="templates")

# databases
blacklist_db = deta.Base("api-blacklist")
reports_db = deta.Base("api-reports")

app.mount("/assets", StaticFiles(directory="templates/assets"), name="assets")


"""
----------------------------------------------------------
                     BASE MODELS
----------------------------------------------------------
"""

class ReportItem(BaseModel):
    domain: str
    description: str


"""
----------------------------------------------------------
                        FUNCTIONS
----------------------------------------------------------
"""

def add_report(domain, description, falsepositive: bool, response):
    if falsepositive:
        report_type = "false-positive"
    else:
        report_type = "report"

    try:
        if "http://" in domain or "https://" in domain:
            x = re.split("https?://(www\.)?([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)", domain)
            # split returns (for example): ['', None, 'google', '.com', '/test/test2']
            # or with a subdomain: ['', None, 'consent', '.google.com', '/test/test2']
            domain = str(x[2]) + str(x[3])
    except IndexError:
        pass

    res = requests.get("https://api.stopmodreposts.org/sites.txt")

    if domain in res.text:
        response.status_code = status.HTTP_409_CONFLICT
        return response, {
            "detail": "Failed to report - domain already listed",
            "already_listed": True,
            "under_review": False,
            "blacklist": False,
            "data": {
                "domain": domain,
                "description": description,
                "false-positive": falsepositive
            }
        }
    elif len(blacklist_db.fetch({"domain": domain}).items) != 0:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return response, {
            "detail": "Failed to report - domain blacklisted",
            "already_listed": False,
            "under_review": False,
            "blacklist": True,
            "data": {
                "domain": domain,
                "description": description,
                "false-positive": falsepositive
            }
        }
    elif len(reports_db.fetch({"domain": domain}).items) != 0:
        response.status_code = status.HTTP_409_CONFLICT
        return response, {
            "detail": "Failed to report - domain already on waitinglist",
            "already_listed": False,
            "under_review": True,
            "blacklist": False,
            "data": {
                "domain": domain,
                "description": description,
                "false-positive": falsepositive
            }
        }
    else:
        reports_db.put({
            "domain": domain,
            "type": report_type,
            "description": description,
            "timestamp": str(datetime.now()),
            "reviewed": False,
            "comment": ""
        })
        return response, {
            "detail": "Success!",
            "already_listed": False,
            "under_review": False,
            "blacklist": False,
            "data": {
                "domain": domain,
                "description": description,
                "false-positive": falsepositive
            }
        }


def get_alert_html(alert_type, title, message):
    if alert_type == "success":
        with open("templates/components/success-alert.html", "r") as f:
            alert_html = f.read()
    elif alert_type == "error":
        with open("templates/components/error-alert.html", "r") as f:
            alert_html = f.read()
    else:
        alert_html = """"""

    if len(alert_html) != 0:
        alert_html = alert_html.format(title, message)
    return alert_html


def verifycaptcha(response: str):
    """
    Verifies that hCaptcha result is valid
    """

    data = {"secret": str(os.getenv("CAPTCHA_SECRET")), "response": response}
    r = requests.post("https://hcaptcha.com/siteverify", data=data)
    if r.status_code == 200 and json.loads(r.text)["success"] == True:
        return True
    else:
        return False

"""
----------------------------------------------------------
                    WEB ENDPOINTS
----------------------------------------------------------
"""

@app.get("/")
def get_root(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request
    })

@app.get("/forms/report")
def get_form_report(request: Request,
                    alert: Optional[str] = None):
    if alert == "success":
        alert_html = get_alert_html(
            alert_type="success",
            title="Submission received",
            message="Your submission was received. It might take a few weeks until your site is added."
        )
    elif alert == "blocked":
        alert_html = get_alert_html(
            alert_type="error",
            title="Submission failed",
            message="Your submission failed because the site you're trying to submit is not allowed to be submitted."
        )
    elif alert == "listed":
        alert_html = get_alert_html(
            alert_type="error",
            title="Submission failed",
            message="Your submission failed because the site you're trying to submit is already listed or under review."
        )
    elif alert == "captcha":
        alert_html = get_alert_html(
            alert_type="error",
            title="Submission failed",
            message="You have to complete the CAPTCHA challenge first."
        )
    else:
        alert_html = """"""
    return templates.TemplateResponse("report.html", {
        "request": request,
        "alert_html": alert_html
    })

@app.get("/forms/falsepositive")
def get_form_falsepositive(request: Request,
                           alert: Optional[str] = None):
    if alert == "success":
        alert_html = get_alert_html(
            alert_type="success",
            title="Submission received",
            message="Your submission was received. It might take a few weeks until your site is added."
        )
    elif alert == "blocked":
        alert_html = get_alert_html(
            alert_type="error",
            title="Submission failed",
            message="Your submission failed because the site you're trying to submit is not allowed to be submitted."
        )
    elif alert == "listed":
        alert_html = get_alert_html(
            alert_type="error",
            title="Submission failed",
            message="Your submission failed because the site you're trying to submit is already listed or under review."
        )
    elif alert == "captcha":
        alert_html = get_alert_html(
            alert_type="error",
            title="Submission failed",
            message="You have to complete the CAPTCHA challenge first."
        )
    else:
        alert_html = """"""
    return templates.TemplateResponse("falsepositive.html", {
        "request": request,
        "alert_html": alert_html
    })

@app.get("/pages/progress")
def get_form_falsepositive(request: Request):
    len_all = len(reports_db.fetch().items)
    len_reviewed = len(reports_db.fetch({"reviewed": True}).items)
    reviewed_percent = int((len_reviewed / len_all) * 100)
    return templates.TemplateResponse("progress.html", {
        "request": request,
        "len_all": len_all,
        "len_reviewed": len_reviewed,
        "reviewed_percent": reviewed_percent
    })


"""
----------------------------------------------------------
                    API ENDPOINTS
----------------------------------------------------------
"""

@app.get("/api/v1/waitlist")
def get_api_waitlist():
    res = reports_db.fetch({"reviewed": False}).items
    final = []
    for site in res:
        final.append({
            "domain": site["domain"],
            "type": site["type"],
            "timestamp": site["timestamp"]
        })
    return final

@app.get("/api/v1/blacklist")
def get_api_blacklist():
    return {"detail": "Blacklist (WIP)"}

@app.post("/api/v1/report", status_code=201)
def post_api_report(response: Response,
                    item: ReportItem,
                    falsepositive: Optional[bool] = False):
    """
    Reporting endpoint for reposting sites and false-positives
    """
    response, res = add_report(
        domain=item.domain,
        description=item.description,
        falsepositive=falsepositive,
        response=response
    )
    return res

@app.post("/api/v1/formreport", status_code=201)
def post_api_report(response: Response,
                    domain: str = Form(None),
                    description: str = Form(None),
                    captcha: str = Form(None, alias="h-captcha-response")):
    """
    Reporting endpoint for reposting sites and false-positives
    """
    if captcha is None:
        return RedirectResponse(url=f"/forms/report?alert=captcha", status_code=status.HTTP_303_SEE_OTHER)
    else:
        if verifycaptcha(captcha) is False:
            return RedirectResponse(url=f"/forms/report?alert=captcha", status_code=status.HTTP_303_SEE_OTHER)

    if domain == None or description == None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Required form fields missing")

    response, res = add_report(
        domain=domain,
        description=description,
        falsepositive=False,
        response=response
    )

    if response.status_code == status.HTTP_409_CONFLICT:
        return RedirectResponse("/forms/report?alert=listed", status_code=status.HTTP_303_SEE_OTHER)
    elif response.status_code == status.HTTP_400_BAD_REQUEST:
        return RedirectResponse("/forms/report?alert=blocked", status_code=status.HTTP_303_SEE_OTHER)
    else:
        return RedirectResponse("/forms/report?alert=success", status_code=status.HTTP_303_SEE_OTHER)


if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8000)