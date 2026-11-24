"""프록시(OPENAI_BASE_URL)로 모델 호출이 되는지, 구조화 출력과 사용량이 돌아오는지 확인한다.
사용: uv run python scripts/check_llm.py [모델이름 ...]   (키·주소는 .env 에서 읽음, 화면에 출력하지 않음)
"""
import json
import os
import sys
import time

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()
client = OpenAI()
try:
    ids = sorted(m.id for m in client.models.list())
    print("사용 가능 모델:", ", ".join(ids) if ids else "(목록 비어 있음)")
except Exception as e:  # 프록시가 목록 조회를 막는 경우
    print("모델 목록 조회 불가:", type(e).__name__)

schema = {"type": "object", "additionalProperties": False,
          "properties": {"state": {"type": "string", "enum": ["affected", "not_affected", "undetermined"]},
                         "reason": {"type": "string"}},
          "required": ["state", "reason"]}
for model in sys.argv[1:] or [os.environ.get("SBOMTRIAGE_MODEL", "")]:
    t = time.time()
    try:
        r = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "버전 2.0이 '<1.5' 범위에 들어가나? 한 문장 이유와 함께 판정해."}],
            response_format={"type": "json_schema", "json_schema": {"name": "v", "strict": True, "schema": schema}})
        u = r.usage
        print(f"[{model}] {time.time()-t:.1f}초 응답={json.loads(r.choices[0].message.content)} "
              f"토큰 입력={u.prompt_tokens} 출력={u.completion_tokens} "
              f"추론={getattr(getattr(u, 'completion_tokens_details', None), 'reasoning_tokens', '없음')}")
    except Exception as e:
        print(f"[{model}] 실패: {type(e).__name__}: {str(e)[:200]}")
