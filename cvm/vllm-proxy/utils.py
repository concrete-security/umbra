
import csv
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class BenchmarkLogger:
    """A simple class to save timing and metadata into a CSV file."""

    def __init__(
        self,
        file_path: Path,
        columns: List[str],
        delimiter: str = ";",
        logger: Optional[logging.Logger] = None,
        reset: bool = False,
    ):
        """Initialize the BenchmarkLogger."""
        self.file_path = file_path
        self.columns = columns
        self.delimiter = delimiter
        self.logger = logger

        self.file_path.parent.mkdir(parents=True, exist_ok=True)

        if reset and self.file_path.exists():
            self.file_path.unlink()
            msg = "Benchmark file reset"
        elif not self.file_path.exists():
            with self.file_path.open("w", newline="") as csvfile:
                writer = csv.writer(csvfile, delimiter=self.delimiter)
                writer.writerow(self.columns)
            msg = "Benchmark file created"
        else:
            msg = "Benchmark file already created"

        if self.logger:
            self.logger.info("%s: '%s'", msg, self.file_path.resolve())

    def append(self, data: Dict[str, Any]):
        """Append a row to the CSV file."""
        invalid_keys = set(data.keys()) - set(self.columns)
        if invalid_keys:
            raise ValueError(
                f"Invalid keys in benchmark data: {invalid_keys}\nAllowed keys: {self.columns}"
            )

        row = [data.get(col, "") for col in self.columns]
        with self.file_path.open("a", newline="") as csvfile:
            writer = csv.writer(csvfile, delimiter=self.delimiter)
            writer.writerow(row)

        if self.logger:
            self.logger.debug("Benchmark row added: %s", row)


def load_txt(path: Union[str, Path]) -> str:
    p = Path(path)
    if p.is_file():
        try:
            return p.read_text(encoding="utf-8").strip()
        except Exception as e:
            print(f"❌ Could not read file `{p}`: {e}")
            return ""

    elif p.is_dir():
        parts = []
        for f in p.rglob("*.txt"):
            try:
                txt = f.read_text(encoding="utf-8", errors="ignore").strip()
                if txt:
                    parts.append(txt)
            except Exception as e:
                print(f"❌ Skip file `{f}`: {e}")
        return "\n".join(parts)

    else:
        raise FileNotFoundError(f"❌ `{path}` is neither a file nor a directory.")
