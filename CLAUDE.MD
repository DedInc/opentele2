You must use claude context mcp to know about project:

Available Tools:

1. index_codebase
Index a codebase directory for hybrid search (BM25 + dense vector).

2. search_code
Search the indexed codebase using natural language queries with hybrid search (BM25 + dense vector).

3. clear_index
Clear the search index for a specific codebase.

4. get_indexing_status
Get the current indexing status of a codebase. Shows progress percentage for actively indexing codebases and completion status for indexed codebases.

Strategy: Without the context engine, you are a very poor tool and work much worse, so you need to wait for 100% indexing and only then use search_code. You cannot switch to dumb grep, search, and other tools because with context it will be more powerful and better. There is no point in using second-rate tools. And follow the logic of how to use tools correctly: get_indexing_status first, because why index a thousand times if it is already indexed? Then immediately after get_indexing_status, perform a test/zero search using search_code (empty or minimal query that should return nothing if indexing is truly valid), because get_indexing_status can falsely report completion (it was indexed once but the index could have been deleted or corrupted later), while a test search_code gives a more accurate real-time status. If both checks confirm full and valid indexing, proceed with the real search; if not, index the data and continue polling with get_indexing_status + test search_code until both confirm readiness, then search.