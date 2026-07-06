"""GraphQL Introspection and Fuzzing Module."""

import httpx
from models import CrawledPage, FormField, FormData

async def parse_graphql_endpoint(url: str, request_params: dict) -> list[CrawledPage]:
    """Sends an Introspection Query to the GraphQL endpoint and converts mutations/queries into forms."""
    
    pages = []
    
    # Standard Introspection Query to discover schema
    introspection_query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        types {
          ...FullType
        }
      }
    }
    fragment FullType on __Type {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args {
          name
          type {
            ...TypeRef
          }
        }
      }
    }
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
          }
        }
      }
    }
    """
    
    headers = request_params.get("headers", {})
    headers["Content-Type"] = "application/json"
    
    async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
        try:
            response = await client.post(url, json={"query": introspection_query}, headers=headers)
            response.raise_for_status()
            schema = response.json()
        except Exception as e:
            # Return a failed page if introspection fails
            return [CrawledPage(
                url=url,
                depth=0,
                status_code=0,
                error=f"GraphQL Introspection failed: {e}",
            )]

    # We will build a single "Virtual Page" that contains all GraphQL operations as HTML Forms
    # This allows standard vulnerability modules (like SQLi, XSS) to attack the GraphQL endpoint seamlessly.
    
    virtual_page = CrawledPage(
        url=url,
        depth=0,
        status_code=200,
        content_type="application/graphql",
        body=str(schema)
    )
    
    try:
        types = schema.get("data", {}).get("__schema", {}).get("types", [])
        query_type_name = schema.get("data", {}).get("__schema", {}).get("queryType", {}).get("name")
        mutation_type_name = schema.get("data", {}).get("__schema", {}).get("mutationType", {}).get("name")
        
        for t in types:
            if t.get("name") in [query_type_name, mutation_type_name]:
                fields = t.get("fields") or []
                for field in fields:
                    operation_name = field.get("name")
                    args = field.get("args") or []
                    
                    # Convert this GraphQL operation into a Form
                    # The form action is the endpoint URL, the method is POST
                    form = FormData(action=url, method="POST")
                    
                    # Add a hidden field to tell the scanner the name of the query
                    form.fields.append(FormField(name="graphql_operation_name", value=operation_name, field_type="hidden"))
                    
                    # Add a field for each argument
                    for arg in args:
                        arg_name = arg.get("name")
                        form.fields.append(FormField(name=arg_name, value="test_fuzz_payload", field_type="text"))
                        
                    virtual_page.forms.append(form)
    except Exception as e:
        virtual_page.error = f"Error parsing GraphQL schema: {e}"
        
    pages.append(virtual_page)
    return pages
