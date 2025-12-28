"""
Pipeline loader - Loads and validates pipeline JSON files.
"""

import json
from pathlib import Path
from typing import Union
from redops.pipelines.schemas import Pipeline


class PipelineLoader:
    """
    Loads pipeline definitions from JSON files and validates them.
    """

    @staticmethod
    def load(path: Union[str, Path]) -> Pipeline:
        """
        Load a pipeline from a JSON file.

        Args:
            path: Path to the pipeline JSON file

        Returns:
            Validated Pipeline object

        Raises:
            FileNotFoundError: If the file doesn't exist
            ValueError: If the JSON is invalid or doesn't match schema
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Pipeline file not found: {path}")

        with open(path, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in pipeline file: {e}")

        # Validate using Pydantic
        try:
            pipeline = Pipeline(**data)
            pipeline.validate_pipeline()
            return pipeline
        except Exception as e:
            raise ValueError(f"Pipeline validation failed: {e}")

    @staticmethod
    def load_from_dict(data: dict) -> Pipeline:
        """
        Load a pipeline from a dictionary.

        Args:
            data: Dictionary containing pipeline definition

        Returns:
            Validated Pipeline object
        """
        pipeline = Pipeline(**data)
        pipeline.validate_pipeline()
        return pipeline

    @staticmethod
    def save(pipeline: Pipeline, path: Union[str, Path]) -> None:
        """
        Save a pipeline to a JSON file.

        Args:
            pipeline: Pipeline object to save
            path: Path to save the JSON file
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            json.dump(pipeline.model_dump(), f, indent=2)
