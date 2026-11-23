"""명령행 진입점. 각 단계 명령은 해당 단계 구현 때 추가한다."""
import typer

app = typer.Typer(help="SW 공급망 스캐닝 에이전트", no_args_is_help=True)


@app.callback()
def main() -> None:
    """SW 공급망 스캐닝 에이전트."""


@app.command()
def version() -> None:
    """버전 출력."""
    from importlib.metadata import version as v

    typer.echo(v("triage"))


if __name__ == "__main__":
    app()
