from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ClaudeExecutionError(Exception):
    detail: str

    def __str__(self) -> str:
        return self.detail

