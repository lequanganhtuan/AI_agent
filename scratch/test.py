from typing import TypedDict, Literal
from langgraph.graph import StateGraph, END

# Đây là "bảng đen" để các node đọc và ghi dữ liệu vào.
class AgentState(TypedDict):
    expression: str      # Biểu thức người dùng nhập vào ban đầu (vd: "3 * 4 + 5")
    current_result: float # Kết quả tính toán trung gian qua các vòng
    next_step: str       # Bước tiếp theo Agent tự quyết định sẽ làm gì
    log: list            # Nhật ký các hành động của Agent qua từng vòng


# Node 1: "Bộ não" phân tích và ra quyết định (Router Node)
def brain_node(state: AgentState):
    print("\n🧠 [Brain Node] Đang phân tích trạng thái hiện tại...")
    
    current_log = state.get("log", [])
    expr = state["expression"]
    
    # Vòng đầu tiên: Chưa có kết quả trung gian, khởi tạo bằng số đầu tiên
    if state["current_result"] == 0 and "*" in expr and "+" in expr:
        # Giả lập việc phân tích chuỗi "3 * 4 + 5"
        # Agent thấy có dấu '*' nên quyết định ưu tiên làm phép nhân trước
        return {
            "next_step": "multiply", 
            "log": current_log + ["Brain: Phát hiện phép nhân cần ưu tiên làm trước."]
        }
    
    # Vòng thứ hai: Đã nhân xong (giả sử ra 12), giờ cần cộng tiếp với 5
    elif state["current_result"] == 12:
        return {
            "next_step": "add", 
            "log": current_log + ["Brain: Phép nhân đã xong. Giờ làm tiếp phép cộng."]
        }
    
    # Vòng cuối: Đã tính toán xong hết
    else:
        return {
            "next_step": "finish", 
            "log": current_log + ["Brain: Mọi phép tính đã hoàn thành. Chuẩn bị trả kết quả."]
        }


# Node 2: Công cụ thực hiện phép nhân (Multiplier Tool)
def multiply_node(state: AgentState):
    print("✖️ [Tool Node] Đang thực hiện phép nhân...")
    current_log = state["log"]
    
    # Giả lập: Lấy 3 * 4 = 12
    return {
        "current_result": 12.0,
        "log": current_log + ["Tool: Đã thực hiện phép nhân 3 * 4 = 12"]
    }


# Node 3: Công cụ thực hiện phép cộng (Adder Tool)
def add_node(state: AgentState):
    print("➕ [Tool Node] Đang thực hiện phép cộng...")
    current_log = state["log"]
    
    # Giả lập: Lấy kết quả cũ (12) + 5 = 17
    new_result = state["current_result"] + 5
    return {
        "current_result": new_result,
        "log": current_log + [f"Tool: Đã thực hiện phép cộng {state['current_result']} + 5 = {new_result}"]
    }

# Hàm này nhìn vào biến `next_step` trong State để chỉ đường cho Agent đi tiếp
def router_logic(state: AgentState) -> Literal["multiply", "add", "end"]:
    if state["next_step"] == "multiply":
        return "multiply"
    elif state["next_step"] == "add":
        return "add"
    else:
        return "end"


# 1. Khởi tạo Graph với State cấu hình sẵn
workflow = StateGraph(AgentState)

# 2. Thêm các Node vào sơ đồ
workflow.add_node("brain", brain_node)
workflow.add_node("multiply", multiply_node)
workflow.add_node("add", add_node)

# 3. Đặt điểm bắt đầu (Entry Point) cho Agent
workflow.set_entry_point("brain")

# 4. Tạo các liên kết (Edges) giữa các Node
# Sau khi Tool chạy xong, bắt buộc phải quay lại Brain để Brain duyệt lại State
workflow.add_edge("multiply", "brain")
workflow.add_edge("add", "brain")

# Cài đặt logic rẽ nhánh cho Brain (Conditional Edges)
workflow.add_conditional_edges(
    "brain",
    router_logic,
    {
        "multiply": "multiply", # Nếu router_logic trả về "multiply", đi tới node multiply
        "add": "add",           # Nếu trả về "add", đi tới node add
        "end": END              # Nếu trả về "end", kết thúc Agent (END là node đặc biệt của LangGraph)
    }
)

agent = workflow.compile()

# --- CHẠY THỬ AGENT ---
if __name__ == "__main__":
    # Khởi tạo dữ liệu ban đầu cho State
    initial_input = {
        "expression": "3 * 4 + 5",
        "current_result": 0.0,
        "next_step": "",
        "log": ["Hệ thống: Nhận yêu cầu tính '3 * 4 + 5'"]
    }
    
    print("=== BẮT ĐẦU CHẠY AGENT ===")
    final_state = agent.invoke(initial_input)
    
    print("\n==========================================")
    print("=== KẾT QUẢ CUỐI CÙNG TRONG STATE ===")
    print(f"Kết quả phép tính: {final_state['current_result']}")
    print("\nNhật ký hoạt động (State Log):")
    for step in final_state['log']:
        print(f" -> {step}")
