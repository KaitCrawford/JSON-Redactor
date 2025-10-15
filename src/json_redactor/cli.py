import typer

from .redactor import redact

app = typer.Typer()
app.command()(redact)


if __name__ == "__main__":
    app()
