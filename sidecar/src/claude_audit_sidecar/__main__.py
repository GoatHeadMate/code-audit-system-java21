import uvicorn


def main() -> None:
    uvicorn.run(
        "claude_audit_sidecar.app:app",
        host="127.0.0.1",
        port=8011,
        reload=False,
    )


if __name__ == "__main__":
    main()
