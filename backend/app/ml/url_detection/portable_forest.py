"""Load and run the saved URL forest without importing sklearn's native code.

The model artifact was produced by scikit-learn. Its fitted trees are stored as
plain NumPy node/value arrays; only the estimator classes themselves require
the native sklearn extensions. This module maps those pickle globals to inert
state containers and performs the same threshold traversal in Python.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Sequence

from joblib.numpy_pickle import NumpyUnpickler


class _EstimatorState:
    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)


class _TreeState(_EstimatorState):
    def __init__(self, *constructor_args: Any) -> None:
        self.constructor_args = constructor_args


class _ModelUnpickler(NumpyUnpickler):
    """Unpickler limited to globals used by this trusted model artifact."""

    _SKLEARN_CLASSES = {
        ("sklearn.ensemble._forest", "RandomForestClassifier"): _EstimatorState,
        ("sklearn.tree._classes", "DecisionTreeClassifier"): _EstimatorState,
        ("sklearn.tree._tree", "Tree"): _TreeState,
    }
    _ARRAY_CLASSES = {
        ("joblib.numpy_pickle", "NumpyArrayWrapper"),
        ("numpy", "dtype"),
        ("numpy", "ndarray"),
        ("numpy._core.multiarray", "scalar"),
    }

    def find_class(self, module: str, name: str) -> Any:
        key = (module, name)
        if key in self._SKLEARN_CLASSES:
            return self._SKLEARN_CLASSES[key]
        if key in self._ARRAY_CLASSES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"Unexpected global in URL model artifact: {module}.{name}"
        )


class PortableRandomForest:
    """Run a fitted RandomForestClassifier using its serialized tree arrays."""

    def __init__(self, fitted_model: Any) -> None:
        self.n_features = int(fitted_model.n_features_in_)
        self.classes = tuple(int(value) for value in fitted_model.classes_)
        self.trees = tuple(fitted_model.estimators_)

        if not self.trees:
            raise ValueError("The saved URL model contains no decision trees.")
        if len(self.classes) != 2:
            raise ValueError("The saved URL model is not a binary classifier.")

        for estimator in self.trees:
            tree = estimator.tree_
            if tree.nodes.shape[0] != tree.node_count:
                raise ValueError("The saved URL model has an invalid tree array.")
            if tree.values.shape != (tree.node_count, 1, len(self.classes)):
                raise ValueError("The saved URL model has an invalid leaf array.")

    @classmethod
    def load(cls, path: Path) -> "PortableRandomForest":
        with path.open("rb") as model_file:
            unpickler = _ModelUnpickler(
                str(path), model_file, ensure_native_byte_order=True
            )
            fitted_model = unpickler.load()
        return cls(fitted_model)

    def predict_proba(self, features: Sequence[float]) -> list[float]:
        if len(features) != self.n_features:
            raise ValueError(
                f"URL model expects {self.n_features} features; got {len(features)}."
            )

        totals = [0.0] * len(self.classes)
        for estimator in self.trees:
            tree = estimator.tree_
            node_index = 0
            while tree.nodes[node_index]["left_child"] != -1:
                node = tree.nodes[node_index]
                feature_index = int(node["feature"])
                if features[feature_index] <= float(node["threshold"]):
                    node_index = int(node["left_child"])
                else:
                    node_index = int(node["right_child"])

            leaf_values = tree.values[node_index, 0]
            leaf_total = float(leaf_values.sum())
            if leaf_total <= 0:
                raise ValueError("The saved URL model contains an empty leaf.")
            for class_index, value in enumerate(leaf_values):
                totals[class_index] += float(value) / leaf_total

        count = float(len(self.trees))
        return [value / count for value in totals]

    def predict(self, features: Sequence[float]) -> int:
        probabilities = self.predict_proba(features)
        return self.classes[max(range(len(probabilities)), key=probabilities.__getitem__)]
