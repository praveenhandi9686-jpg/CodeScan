import os
os.environ["DATABASE_URL"] = "sqlite:///:memory:"   # app.py builds a module-level app on import
os.environ.pop("VERCEL", None)
os.environ["COMPILER_CHECKS"] = "false"   # keep the accuracy corpus identical on every machine; compiler tests switch it on
