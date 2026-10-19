//! Conversions between Python values and the session JSON of the core.
//!
//! Dicts keep their key order both ways (`serde_json` `preserve_order`), so a
//! dict written by `profile_to_session_json` dumps as 1.5.0's JSON.

use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use serde_json::{Map, Number, Value};

/// The deepest nesting accepted, the parse limit of `serde_json`.
const MAX_DEPTH: usize = 128;

/// `value` as JSON: `None`, `bool`, `int` (64 bits), finite `float`, `str`,
/// `list`/`tuple` and `dict` with `str` keys.
pub(crate) fn to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    to_json_at(value, 0)
}

/// The dict `dict` as a JSON object, keys in its order.
pub(crate) fn to_json_object(dict: &Bound<'_, PyDict>) -> PyResult<Map<String, Value>> {
    to_json_object_at(dict, 0)
}

fn to_json_at(value: &Bound<'_, PyAny>, depth: usize) -> PyResult<Value> {
    if depth > MAX_DEPTH {
        return Err(PyValueError::new_err("the JSON value nests too deeply"));
    }
    if value.is_none() {
        return Ok(Value::Null);
    }
    // `bool` is an `int` subclass, so it is tested first.
    if let Ok(flag) = value.cast::<PyBool>() {
        return Ok(Value::Bool(flag.is_true()));
    }
    if value.is_instance_of::<PyInt>() {
        if let Ok(number) = value.extract::<i64>() {
            return Ok(number.into());
        }
        if let Ok(number) = value.extract::<u64>() {
            return Ok(number.into());
        }
        return Err(PyValueError::new_err("a JSON integer must fit in 64 bits"));
    }
    if let Ok(float) = value.cast::<PyFloat>() {
        return Number::from_f64(float.value())
            .map(Value::Number)
            .ok_or_else(|| PyValueError::new_err("JSON has no NaN or infinity"));
    }
    if let Ok(text) = value.cast::<PyString>() {
        return Ok(Value::String(text.to_cow()?.into_owned()));
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        return to_json_object_at(dict, depth + 1).map(Value::Object);
    }
    if value.is_instance_of::<PyList>() || value.is_instance_of::<PyTuple>() {
        return value
            .try_iter()?
            .map(|item| to_json_at(&item?, depth + 1))
            .collect::<PyResult<Vec<_>>>()
            .map(Value::Array);
    }
    Err(PyTypeError::new_err(format!(
        "{} is not JSON serializable",
        value.get_type().name()?
    )))
}

fn to_json_object_at(dict: &Bound<'_, PyDict>, depth: usize) -> PyResult<Map<String, Value>> {
    let mut map = Map::new();
    for (key, item) in dict.iter() {
        let key = key
            .cast_into::<PyString>()
            .map_err(|_| PyTypeError::new_err("JSON object keys must be str"))?;
        map.insert(key.to_cow()?.into_owned(), to_json_at(&item, depth)?);
    }
    Ok(map)
}

/// `value` as Python: `None`, `bool`, `int`, `float`, `str`, `list` and
/// `dict`, keys in order.
pub(crate) fn from_json<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match value {
        Value::Null => py.None().into_bound(py),
        Value::Bool(flag) => PyBool::new(py, *flag).to_owned().into_any(),
        Value::Number(number) => {
            if let Some(int) = number.as_i64() {
                int.into_pyobject(py)?.into_any()
            } else if let Some(int) = number.as_u64() {
                int.into_pyobject(py)?.into_any()
            } else {
                let float = number
                    .as_f64()
                    .ok_or_else(|| PyValueError::new_err("a JSON number is not representable"))?;
                PyFloat::new(py, float).into_any()
            }
        }
        Value::String(text) => PyString::new(py, text).into_any(),
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(from_json(py, item)?)?;
            }
            list.into_any()
        }
        Value::Object(map) => from_json_object(py, map)?.into_any(),
    })
}

/// The JSON object `map` as a dict, keys in its order.
pub(crate) fn from_json_object<'py>(
    py: Python<'py>,
    map: &Map<String, Value>,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(py);
    for (key, item) in map {
        dict.set_item(key, from_json(py, item)?)?;
    }
    Ok(dict)
}
