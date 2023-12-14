import argparse
from pprint import pprint as pp

import jsonref
import yaml


def openapi_to_functions(openapi_spec):
    """
    Convert OpenAPI specification to OpenAI function calling syntax.
    Reference:
    https://cookbook.openai.com/examples/function_calling_with_an_openapi_spec
    """
    functions = []

    for path, methods in openapi_spec['paths'].items():
        for method, spec_with_ref in methods.items():
            # 1. Resolve JSON references.
            spec = jsonref.replace_refs(spec_with_ref)

            # 2. Extract a name for the functions.
            function_name = spec.get('operationId')

            # 3. Extract a description and parameters.
            desc = spec.get('description') or spec.get('summary', '')

            schema = {'type': 'object', 'properties': {}}

            req_body = (
                spec.get('requestBody', {})
                .get('content', {})
                .get('application/json', {})
                .get('schema')
            )
            if req_body:
                schema['properties']['requestBody'] = req_body

            params = spec.get('parameters', [])
            if params:
                param_properties = {
                    param['name']: param['schema']
                    for param in params
                    if 'schema' in param
                }
                schema['properties']['parameters'] = {
                    'type': 'object',
                    'properties': param_properties,
                }

            functions.append(
                {'name': function_name, 'description': desc, 'parameters': schema}
            )

    return functions


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Convert OpenAPI spec to OpenAI function calling'
    )
    parser.add_argument('--openapi', help="openapi spec file")
    args = parser.parse_args()

    with open(args.openapi, 'r') as f:
        openapi_spec = yaml.safe_load(f)

    functions = openapi_to_functions(openapi_spec)

    for function in functions:
        pp(function)
