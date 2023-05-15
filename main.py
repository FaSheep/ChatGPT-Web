import datetime
import hashlib
import json
import re

import requests
from flask import Flask, jsonify, render_template, request, session
import os
import uuid
from LRU_cache import LRUCache
import threading
import pickle
import asyncio
import yaml
from sqlalchemy import create_engine, select
# from sqlalchemy.orm import sessionmaker
# from User import User
from sqlalchemy.orm import declarative_base, Session, relationship
from sqlalchemy import Column, String, Integer, ForeignKey, exists
from sqlalchemy.dialects.mysql import LONGTEXT
# from sqlalchemy.ext.declarative import declarative_base

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)

with open("config.yaml", "r", encoding="utf-8") as f:
    config = yaml.load(f, Loader=yaml.FullLoader)
    if 'HTTPS_PROXY' in config:
        if os.environ.get('HTTPS_PROXY') is None:   # 优先使用环境变量中的代理，若环境变量中没有代理，则使用配置文件中的代理
            os.environ['HTTPS_PROXY'] = config['HTTPS_PROXY']
    PORT = config['PORT']
    API_KEY = config['OPENAI_API_KEY']
    CHAT_CONTEXT_NUMBER_MAX = config['CHAT_CONTEXT_NUMBER_MAX']     # 连续对话模式下的上下文最大数量 n，即开启连续对话模式后，将上传本条消息以及之前你和GPT对话的n-1条消息
    USER_SAVE_MAX = config['USER_SAVE_MAX']     # 设置最多存储n个用户，当用户过多时可适当调大
    SQL_SEVER = config['SQL_SERVER']
    SQL_PORT = config['SQL_PORT']
    SQL_USERNAME = config['SQL_USERNAME']
    SQL_PASSWORD = config['SQL_PASSWORD']
    API_URL = config['API_URL']

url = API_URL + "/v1/chat/completions"
subscription_url = API_URL + "/v1/dashboard/billing/subscription"
# billing_url = f"{API_URL}/v1/dashboard/billing/usage?start_date={start_date}&end_date={end_date}"

if os.getenv("DEPLOY_ON_RAILWAY") is not None:  # 如果是在Railway上部署，需要删除代理
    os.environ.pop('HTTPS_PROXY', None)

API_KEY = os.getenv("OPENAI_API_KEY", default=API_KEY)  # 如果环境变量中设置了OPENAI_API_KEY，则使用环境变量中的OPENAI_API_KEY
PORT = os.getenv("PORT", default=PORT)  # 如果环境变量中设置了PORT，则使用环境变量中的PORT
SQL_SEVER = os.getenv("SQL_SERVER", default=SQL_SEVER)
SQL_PORT = os.getenv("SQL_PORT", default=SQL_PORT)
SQL_USERNAME = os.getenv("SQL_USERNAME", default=SQL_USERNAME)
SQL_PASSWORD = os.getenv("SQL_PASSWORD", default=SQL_PASSWORD)

STREAM_FLAG = True  # 是否开启流式推送
USER_DICT_FILE = "all_user_dict_v2.pkl"  # 用户信息存储文件（包含版本）
lock = threading.Lock()  # 用于线程锁

# User ORM 对象
Base = declarative_base()
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(16), unique=True)
    password = Column(String(64))
    balance = Column(Integer)
    history = relationship(
        "History", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"User(id={self.id!r}, username={self.username!r}, password={self.password!r})"

class History(Base):
    __tablename__ = "history"
    id = Column(Integer, primary_key=True)
    content = Column(LONGTEXT)
    role = Column(String(10))
    chat_name = Column(String(16))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    user = relationship("User", back_populates="history")

    def __repr__(self):
        return f"{{\"content\":\"{self.content!r}\",\"role\":\"{self.role!r}\"}}"

class Key(Base):
    __tablename__ = "keys"
    id = Column(Integer, primary_key=True)
    value = Column(String(16), unique=True)
    balance = Column(Integer)

engine = create_engine(
    f"mysql://{SQL_USERNAME}:{SQL_PASSWORD}@{SQL_SEVER}:{SQL_PORT}/chat?charset=utf8",
    echo = True,
    future=True
)

Base.metadata.create_all(bind=engine, checkfirst=True)

# declarative_base().metadata.create_all(engine)


project_info = "## ChatGPT 网页版    \n" \
               " Code From  " \
               "[ChatGPT-Web](https://github.com/FaSheep/ChatGPT-Web)  \n" \
               "发送`帮助`可获取帮助  \n"


def get_response_from_ChatGPT_API(message_context, apikey):
    """
    从ChatGPT API获取回复
    :param apikey:
    :param message_context: 上下文
    :return: 回复
    """
    if apikey is None:
        apikey = API_KEY

    header = {"Content-Type": "application/json",
              "Authorization": "Bearer " + apikey}

    data = {
        "model": "gpt-3.5-turbo",
        "messages": message_context
    }

    try:
        response = requests.post(url, headers=header, data=json.dumps(data))
        response = response.json()
        # 判断是否含 choices[0].message.content
        if "choices" in response \
                and len(response["choices"]) > 0 \
                and "message" in response["choices"][0] \
                and "content" in response["choices"][0]["message"]:
            data = response["choices"][0]["message"]["content"]
        else:
            data = str(response)

    except Exception as e:
        print(e)
        return str(e)

    return data


def get_message_context(message_history, have_chat_context, chat_with_history):
    """
    获取上下文
    :param message_history:
    :param have_chat_context:
    :param chat_with_history:
    :return:
    """
    message_context = []
    total = 0
    if chat_with_history:
        num = min([len(message_history), CHAT_CONTEXT_NUMBER_MAX, have_chat_context])
        # 获取所有有效聊天记录
        valid_start = 0
        valid_num = 0
        for i in range(len(message_history) - 1, -1, -1):
            message = message_history[i]
            if message['role'] in {'assistant', 'user'}:
                valid_start = i
                valid_num += 1
            if valid_num >= num:
                break

        for i in range(valid_start, len(message_history)):
            message = message_history[i]
            if message['role'] in {'assistant', 'user'}:
                message_context.append(message)
                total += len(message['content'])
    else:
        message_context.append(message_history[-1])
        total += len(message_history[-1]['content'])

    print(f"len(message_context): {len(message_context)} total: {total}",)
    return message_context


def handle_messages_get_response(message, apikey, message_history, have_chat_context, chat_with_history):
    """
    处理用户发送的消息，获取回复
    :param message: 用户发送的消息
    :param apikey:
    :param message_history: 消息历史
    :param have_chat_context: 已发送消息数量上下文(从重置为连续对话开始)
    :param chat_with_history: 是否连续对话
    """
    stmt = select(User).where(User.username==session['userz_id'])
    with Session(engine) as sqlsession:
        user = sqlsession.scalars(stmt).one()
        user.history.append(History(content=message, role="user"))

        message_history.append({"role": "user", "content": message})
        message_context = get_message_context(message_history, have_chat_context, chat_with_history)
        response = get_response_from_ChatGPT_API(message_context, apikey)
        message_history.append({"role": "assistant", "content": response})

        user.history.append(History(content=message, role="assistant"))

        count = 0
        for s in response:
            if '\u4e00' <= s <= '\u9fff':
                count += 1
        user.balance = max(user.balance - (len(response.split()) + count), 0)

        sqlsession.commit()
    
    # 换行打印messages_history
    # print("message_history:")
    # for i, message in enumerate(message_history):
    #     if message['role'] == 'user':
    #         print(f"\t{i}:\t{message['role']}:\t\t{message['content']}")
    #     else:
    #         print(f"\t{i}:\t{message['role']}:\t{message['content']}")

    return response


def get_response_stream_generate_from_ChatGPT_API(message_context, apikey, message_history, username):
    """
    从ChatGPT API获取回复
    :param apikey:
    :param message_context: 上下文
    :return: 回复
    """
    if apikey is None:
        apikey = API_KEY

    header = {"Content-Type": "application/json",
              "Authorization": "Bearer " + apikey}

    data = {
        "model": "gpt-3.5-turbo",
        "messages": message_context,
        "stream": True
    }
    print("开始流式请求")
    # 请求接收流式数据 动态print
    try:
        response = requests.request("POST", url, headers=header, json=data, stream=True)

        def generate():
            stream_content = str()
            one_message = {"role": "assistant", "content": stream_content}
            message_history.append(one_message)
            print('============', one_message)
            stmt = select(User).where(User.username==username)
            # with Session(engine) as sqlsession:
            sqlsession = Session(engine)
            
            # sqlsession.commit()
            
            i = 0
            for line in response.iter_lines():
                # print(str(line))
                line_str = str(line, encoding='utf-8')
                if line_str.startswith("data:"):
                    if line_str.startswith("data: [DONE]"):
                        asyncio.run(save_all_user_dict())
                        break
                    line_json = json.loads(line_str[5:])
                    if 'choices' in line_json:
                        if len(line_json['choices']) > 0:
                            choice = line_json['choices'][0]
                            if 'delta' in choice:
                                delta = choice['delta']
                                if 'role' in delta:
                                    role = delta['role']
                                elif 'content' in delta:
                                    delta_content = delta['content']
                                    i += 1
                                    if i < 40:
                                        print(delta_content, end="")
                                    elif i == 40:
                                        print("......")
                                    stream_content += delta_content
                                    one_message['content'] = one_message['content'] + delta_content
                                    yield delta_content

                elif len(line_str.strip()) > 0:
                    print(line_str)
                    yield line_str
                
            user = sqlsession.scalars(stmt).one()
            user.history.append(History(content=stream_content, role="assistant"))
            count = 0
            for s in stream_content:
                if '\u4e00' <= s <= '\u9fff':
                    count += 1
            user.balance = max(user.balance - (len(stream_content.split()) + count), 0)
            sqlsession.commit()
            sqlsession.close()

    except Exception as e:
        ee = e

        def generate():
            yield "request error:\n" + str(ee)

    return generate


def handle_messages_get_response_stream(message, apikey, message_history, have_chat_context, chat_with_history):

    stmt = select(User).where(User.username==session['user_id'])
    # print(stmt)
    with Session(engine) as sqlsession:
        user = sqlsession.scalars(stmt).one()
        user.history.append(History(content=message, role="user"))
        sqlsession.commit()

    message_history.append({"role": "user", "content": message})
    asyncio.run(save_all_user_dict())
    message_context = get_message_context(message_history, have_chat_context, chat_with_history)
    generate = get_response_stream_generate_from_ChatGPT_API(message_context, apikey, message_history, session['user_id'])
    return generate


def check_session(current_session):
    """
    检查session，如果不存在则创建新的session
    :param current_session: 当前session
    :return: 当前session
    """
    if current_session.get('session_id') is not None:
        print("existing session, session_id:\t", current_session.get('session_id'))
    else:
        current_session['session_id'] = uuid.uuid1()
        print("new session, session_id:\t", current_session.get('session_id'))
    return current_session['session_id']


def check_user_bind(current_session):
    """
    检查用户是否绑定，如果没有绑定则重定向到index
    :param current_session: 当前session
    :return: 当前session
    """
    if current_session.get('user_id') is None:
        return False
    return True


def get_user_info(user_id):
    """
    获取用户信息
    :param user_id: 用户id
    :return: 用户信息
    """
    
    lock.acquire()
    user_info = all_user_dict.get(user_id)
    lock.release()
    return user_info


# 进入主页
@app.route('/', methods=['GET', 'POST'])
def index():
    """
    主页
    :return: 主页
    """
    check_session(session)
    return render_template('index.html')


@app.route('/loadHistory', methods=['GET', 'POST'])
def load_messages():
    """
    加载聊天记录
    :return: 聊天记录
    """
    check_session(session)
    if session.get('user_id') is None:
        messages_history = [{"role": "assistant", "content": project_info},
                            {"role": "assistant", "content": "#### 当前浏览器会话为首次请求\n"
                                                             "#### 请输入已有用户`id`或创建新的用户`id`。\n"
                                                             "- 已有用户`id`请在输入框中直接输入\n"
                                                             "- 创建新的用户`id`请在输入框中输入`new:xxx`,其中`xxx`为你的自定义id，请牢记\n"
                                                             "- 输入`帮助`以获取帮助提示"}]
    else:
        user_info = get_user_info(session.get('user_id'))
        chat_id = user_info['selected_chat_id']
        messages_history = user_info['chats'][chat_id]['messages_history']
        print(f"用户({session.get('user_id')})加载聊天记录，共{len(messages_history)}条记录")
        
        
        # query = sqlsession.query(User).filter(User.username==session['user_id'])
        # if not sqlsession.query(query.exists()).scalar():
        #     return "user not exist"
        # sha256 = hashlib.sha256()
        # sha256.update(password.encode('utf-8'))
        
        with Session(engine) as sqlsession:
            history = sqlsession.query(History).join(History.user).filter(User.username==session['user_id']).all()
            
            # history = sqlsession.scalars(stmt)
            messages_history = []
            # print(user.history)
            for h in history:
            #     # messages_history.append(h.__dict__())
                h_dict = {'content':h.content, 'role':h.role}
                messages_history.append(h_dict)
            

    return {"code": 0, "data": messages_history, "message": ""}


@app.route('/loadChats', methods=['GET', 'POST'])
def load_chats():
    """
    加载聊天联系人
    :return: 聊天联系人
    """
    check_session(session)
    if not check_user_bind(session):
        chats = []

    else:
        user_info = get_user_info(session.get('user_id'))
        chats = []
        for chat_id, chat_info in user_info['chats'].items():
            chats.append(
                {"id": chat_id, "name": chat_info['name'], "selected": chat_id == user_info['selected_chat_id'], "messages_total": len(user_info['chats'][chat_id]['messages_history'])})

    return {"code": 0, "data": chats, "message": ""}


def new_chat_dict(user_id, name, send_time):
    return {"chat_with_history": False,
            "have_chat_context": 0,  # 从每次重置聊天模式后开始重置一次之后累计
            "name": name,
            "messages_history": [{"role": "assistant", "content": project_info},
                                 {"role": "system", "content": f"当前对话的用户id为{user_id}"},
                                 {"role": "system", "content": send_time},
                                 {"role": "system", "content": f"你已添加了{name}，现在可以开始聊天了。"},
                                 ]}


def new_user_dict(user_id, send_time):
    chat_id = str(uuid.uuid1())
    user_dict = {"chats": {chat_id: new_chat_dict(user_id, "默认对话", send_time)},
                 "selected_chat_id": chat_id,
                 "default_chat_id": chat_id}

    user_dict['chats'][chat_id]['messages_history'].insert(1, {"role": "assistant",
                                                               "content": "- 创建新的用户id成功，请牢记该id  \n"
                                                                          "- 您可以使用该网站提供的通用apikey进行对话，"
                                                                          "也可以输入 set_apikey:[your_apikey](https://platform.openai.com/account/api-keys) "
                                                                          "来设置用户专属apikey"})
    return user_dict


def get_balance(apikey):
    head = ""
    if apikey is not None:
        head = "###  用户专属api key余额  \n"
    else:
        head = "### 通用api key  \n"
        apikey = API_KEY

    headers = {
        "Authorization": "Bearer " + apikey,
        "Content-Type": "application/json"
    }
    subscription_response = requests.get(subscription_url, headers=headers)
    if subscription_response.status_code == 200:
        data = subscription_response.json()
        total = data.get("hard_limit_usd")
    else:
        return head+subscription_response.text

    # start_date设置为今天日期前99天
    start_date = (datetime.datetime.now() - datetime.timedelta(days=99)).strftime("%Y-%m-%d")
    # end_date设置为今天日期+1
    end_date = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%Y-%m-%d")
    billing_url = f"{API_URL}/v1/dashboard/billing/usage?start_date={start_date}&end_date={end_date}"
    billing_response = requests.get(billing_url, headers=headers)
    if billing_response.status_code == 200:
        data = billing_response.json()
        total_usage = data.get("total_usage") / 100
        daily_costs = data.get("daily_costs")
        days = min(5, len(daily_costs))
        recent = f"##### 最近{days}天使用情况  \n"
        for i in range(days):
            cur = daily_costs[-i-1]
            date = datetime.datetime.fromtimestamp(cur.get("timestamp")).strftime("%Y-%m-%d")
            line_items = cur.get("line_items")
            cost = 0
            for item in line_items:
                cost += item.get("cost")
            recent += f"\t{date}\t{cost / 100} \n"
    else:
        return head+billing_response.text

    return head+f"\n#### 总额:\t{total:.4f}  \n" \
                f"#### 已用:\t{total_usage:.4f}  \n" \
                f"#### 剩余:\t{total-total_usage:.4f}  \n" \
                f"\n"+recent


@app.route('/signup', methods=['GET', 'POST'])
def sign_up():
    username = request.values.get("username").strip()
    password = request.values.get("password").strip()

    # 非法输入检测
    if len(username) > 16 or len(password) > 32:
        return {"code": 400, "data": "data too long"}
    if not re.search(u'^[a-zA-Z0-9]+$', username):
        return {"code": 400, "data": "username unexpect"}
    if not re.search(u'^[_a-zA-Z0-9@#\?!\.]+$', password):
        return {"code": 400, "data": "password unexpect"}
    
    with Session(engine) as sqlsession:
        query = sqlsession.query(User).filter(User.username==username)
        if sqlsession.query(query.exists()).scalar():
            return {"code": 400, "data": "user exist"}
        sha256 = hashlib.sha256()
        sha256.update(password.encode('utf-8'))
        sqlsession.add(User(
            username=username,
            password=sha256.hexdigest(),
            balance=0,
            history=[]
        ))
        sqlsession.commit()
    return {"code": 200, "data": "sign up successfully"}

@app.route('/signin', methods=['GET', 'POST'])
def sign_in():
    username = request.values.get("username").strip()
    password = request.values.get("password").strip()

    # 非法输入检测
    if len(username) > 16 or len(password) > 32:
        return {"code": 400, "data": "data too long"}
    if not re.search(u'^[a-zA-Z0-9]+$', username):
        return {"code": 400, "data": "username unexpect"}
    if not re.search(u'^[_a-zA-Z0-9@#\?!\.]+$', password):
        return {"code": 400, "data": "password unexpect"}
    
    with Session(engine) as sqlsession:
        query = sqlsession.query(User).filter(User.username==username)
        if sqlsession.query(query.exists()).scalar():
        # if not sqlsession.query(User).filter(User.username==username).exists():
            return {"code": 400, "data": "user not exist"}
        sha256 = hashlib.sha256()
        sha256.update(password.encode('utf-8'))
        
        stmt = select(User).where(User.username==username)
        with Session(engine) as sqlsession:
            user = sqlsession.scalars(stmt).one()
            if user.password == sha256.hexdigest():
                session['user_id'] = username
                return {"code": 200, "data": "sign in successfully"}
            else:
                return {"code": 200, "data": "error password"}
    
@app.route('/recharge', methods=['GET', 'POST'])
def recharge():
    key = request.values.get("key").strip()
    with Session(engine) as sqlsession:
        query = sqlsession.query(Key).filter(Key.value==key)
        if not sqlsession.query(query.exists()).scalar():
            return {"code": 400, "data": "key not exist"}
        key_obj = sqlsession.query(Key).filter(Key.value==key).one()
        user = sqlsession.query(User).filter(User.username==session['user_id']).one()
        if key_obj.balance <= 0:
            return {"code": 400, "data": "key already used"}
        user.balance += key_obj.balance
        key_obj.balance = 0
        sqlsession.commit()
    return {"code": 200, "data": "recharge successfully"}

@app.route('/checkbalance', methods=['GET', 'POST'])
def checkbalance():
    with Session(engine) as sqlsession:
        user = sqlsession.query(User).filter(User.username==session['user_id']).one()
        return {"code": 200, "data": user.balance}

@app.route('/returnMessage', methods=['GET', 'POST'])
def return_message():
    """
    获取用户发送的消息，调用get_chat_response()获取回复，返回回复，用于更新聊天框
    :return:
    """
    check_session(session)
    send_message = request.values.get("send_message").strip()
    send_time = request.values.get("send_time").strip()
    url_redirect = "url_redirect:/"
    if send_message == "帮助":
        return "### 帮助\n" \
               "1. 输入`new:username password`创建新的用户\n " \
               "2. 输入`id:your_id`切换到已有用户id，新会话时无需加`id:`进入已有用户\n" \
               "3. 输入`set_apikey:`[your_apikey](https://platform.openai.com/account/api-keys)设置用户专属apikey，`set_apikey:none`可删除专属key\n" \
               "4. 输入`rename_id:xxx`可将当前用户id更改\n" \
               "5. 输入`查余额`可获得余额信息及最近几天使用量\n" \
               "6. 输入`帮助`查看帮助信息"

    if session.get('user_id') is None:  # 如果当前session未绑定用户
        print("当前会话为首次请求，用户输入:\t", send_message)
        if send_message.startswith("new:"):

            str = send_message.split(":")[1]
            user_id = str.split(" ")[0]
            password = str.split(" ")[1]

            if len(user_id) > 16 or len(password) > 32:
                return "data too long"
            if not re.search(u'^[a-zA-Z0-9]+$', user_id):
                return "username unexpect"
            if not re.search(u'^[_a-zA-Z0-9@#\?!\.]+$', password):
                return "password unexpect"
            
            with Session(engine) as sqlsession:
                query = sqlsession.query(User).filter(User.username==user_id)
                if sqlsession.query(query.exists()).scalar():
                    return {"code": 400, "data": "user exist"}
                sha256 = hashlib.sha256()
                sha256.update(password.encode('utf-8'))
                print('密码：', sha256.hexdigest())
                sqlsession.add(User(
                    username=user_id,
                    password=sha256.hexdigest(),
                    balance=0,
                    history=[]
                ))
                sqlsession.commit()
            # return {"code": 200, "data": "sign up successfully"}

            

            # stmt = select(User).where(User.username==user_id)
            # with Session(engine) as sqlsession:
            #     if sqlsession.scalars(stmt).one().exist():
            #         sqlsession.add(User(username=user_id, password=0, balance=0, history=[]))
            #         sqlsession.commit()

            if user_id in all_user_dict:
                session['user_id'] = user_id
                return url_redirect
            user_dict = new_user_dict(user_id, send_time)
            lock.acquire()
            all_user_dict.put(user_id, user_dict)  # 默认普通对话
            lock.release()
            print("创建新的用户id:\t", user_id)
            session['user_id'] = user_id
            return url_redirect
        else:
            user_id = send_message.split(" ")[0]
            password = send_message.split(" ")[1]
            if len(user_id) > 16 or len(password) > 32:
                return "data too long"
            if not re.search(u'^[a-zA-Z0-9]+$', user_id):
                return "username unexpect"
            if not re.search(u'^[_a-zA-Z0-9@#\?!\.]+$', password):
                return "password unexpect"
            
            with Session(engine) as sqlsession:
                query = sqlsession.query(User).filter(User.username==user_id)
                if not sqlsession.query(query.exists()).scalar():
                    return "user not exist"
                sha256 = hashlib.sha256()
                sha256.update(password.encode('utf-8'))
                
                stmt = select(User).where(User.username==user_id)
                with Session(engine) as sqlsession:
                    user = sqlsession.scalars(stmt).one()
                    if not user.password == sha256.hexdigest():
                        # session['user_id'] = username
                        # return {"code": 200, "data": "sign in successfully"}
                        return "error password"

            user_info = get_user_info(user_id) 
            if user_info is None:
                return "用户id不存在，请重新输入或创建新的用户id"
            else:
                session['user_id'] = user_id
                print("已有用户id:\t", user_id)
                # 重定向到index
                return url_redirect
    else:  # 当存在用户id时
        if send_message.startswith("id:"):
            str = send_message.split(":")[1].strip()

            user_id = str.split(" ")[0]
            password = str.split(" ")[1]
            if len(user_id) > 16 or len(password) > 32:
                return "data too long"
            if not re.search(u'^[a-zA-Z0-9]+$', user_id):
                return "username unexpect"
            if not re.search(u'^[_a-zA-Z0-9@#\?!\.]+$', password):
                return "password unexpect"
            
            with Session(engine) as sqlsession:
                query = sqlsession.query(User).filter(User.username==user_id)
                if not sqlsession.query(query.exists()).scalar():
                    return "user not exist"
                sha256 = hashlib.sha256()
                sha256.update(password.encode('utf-8'))
                
                stmt = select(User).where(User.username==user_id)
                with Session(engine) as sqlsession:
                    user = sqlsession.scalars(stmt).one()
                    if not user.password == sha256.hexdigest():
                        # session['user_id'] = username
                        # return {"code": 200, "data": "sign in successfully"}
                        return "error password"

            user_info = get_user_info(user_id)
            if user_info is None:
                return "用户id不存在，请重新输入或创建新的用户id"
            else:
                session['user_id'] = user_id
                print("切换到已有用户id:\t", user_id)
                # 重定向到index
                return url_redirect
        elif send_message.startswith("new:"):
            str = send_message.split(":")[1]
            user_id = str.split(" ")[0]
            password = str.split(" ")[1]

            if len(user_id) > 16 or len(password) > 32:
                return "data too long"
            if not re.search(u'^[a-zA-Z0-9]+$', user_id):
                return "username unexpect"
            if not re.search(u'^[_a-zA-Z0-9@#\?!\.]+$', password):
                return "password unexpect"
            
            with Session(engine) as sqlsession:
                query = sqlsession.query(User).filter(User.username==user_id)
                if sqlsession.query(query.exists()).scalar():
                    return {"code": 400, "data": "user exist"}
                sha256 = hashlib.sha256()
                sha256.update(password.encode('utf-8'))
                sqlsession.add(User(
                    username=user_id,
                    password=sha256.hexdigest(),
                    balance=0,
                    history=[]
                ))
                sqlsession.commit()

            if user_id in all_user_dict:
                return "用户id已存在，请重新输入或切换到已有用户id"
            session['user_id'] = user_id
            user_dict = new_user_dict(user_id, send_time)
            lock.acquire()
            all_user_dict.put(user_id, user_dict)
            lock.release()
            print("创建新的用户id:\t", user_id)
            return url_redirect
        elif send_message.startswith("delete:"):  # 删除用户
            user_id = send_message.split(":")[1]
            if user_id != session.get('user_id'):
                return "只能删除当前会话的用户id"
            else:
                lock.acquire()
                all_user_dict.delete(user_id)
                lock.release()
                session['user_id'] = None
                print("删除用户id:\t", user_id)
                # 异步存储all_user_dict
                asyncio.run(save_all_user_dict())
                return url_redirect
        elif send_message.startswith("set_apikey:"):
            apikey = send_message.split(":")[1]
            user_info = get_user_info(session.get('user_id'))
            user_info['apikey'] = apikey
            print("设置用户专属apikey:\t", apikey)
            return "设置用户专属apikey成功"
        elif send_message.startswith("rename_id:"):
            new_user_id = send_message.split(":")[1]
            user_info = get_user_info(session.get('user_id'))
            if new_user_id in all_user_dict:
                return "用户id已存在，请重新输入"
            else:
                lock.acquire()
                all_user_dict.delete(session['user_id'])
                all_user_dict.put(new_user_id, user_info)
                lock.release()
                session['user_id'] = new_user_id
                asyncio.run(save_all_user_dict())
                print("修改用户id:\t", new_user_id)
                return f"修改成功,请牢记新的用户id为:{new_user_id}"
        elif send_message == "查余额":
            user_info = get_user_info(session.get('user_id'))
            apikey = user_info.get('apikey')

            stmt = select(User).where(User.username==session['user_id'])
            with Session(engine) as sqlsession:
                for user in sqlsession.scalar(stmt):
                    print(user)

            return get_balance(apikey)
        else:  # 处理聊天数据
            user_id = session.get('user_id')
            print(f"用户({user_id})发送消息:{send_message}")
            user_info = get_user_info(user_id)
            chat_id = user_info['selected_chat_id']
            messages_history = user_info['chats'][chat_id]['messages_history']
            chat_with_history = user_info['chats'][chat_id]['chat_with_history']
            apikey = user_info.get('apikey')
            if chat_with_history:
                user_info['chats'][chat_id]['have_chat_context'] += 1
            if send_time != "":
                messages_history.append({'role': 'system', "content": send_time})

                stmt = select(User).where(User.username==session['user_id'])
                with Session(engine) as sqlsession:
                    user = sqlsession.scalars(stmt).one()
                    user.history.append(History(content=send_time, role="system"))
                    sqlsession.commit()
            if not STREAM_FLAG:
                content = handle_messages_get_response(send_message, apikey, messages_history,
                                                       user_info['chats'][chat_id]['have_chat_context'],
                                                       chat_with_history)

                print(f"用户({session.get('user_id')})得到的回复消息:{content[:40]}...")
                if chat_with_history:
                    user_info['chats'][chat_id]['have_chat_context'] += 1
                # 异步存储all_user_dict
                asyncio.run(save_all_user_dict())
                return content
            else:
                generate = handle_messages_get_response_stream(send_message, apikey, messages_history,
                                                               user_info['chats'][chat_id]['have_chat_context'],
                                                               chat_with_history)
                print(generate)
                if chat_with_history:
                    user_info['chats'][chat_id]['have_chat_context'] += 1

                return app.response_class(generate(), mimetype='application/json')


async def save_all_user_dict():
    """
    异步存储all_user_dict
    :return:
    """
    await asyncio.sleep(0)
    lock.acquire()
    with open(USER_DICT_FILE, "wb") as f:
        pickle.dump(all_user_dict, f)
    # print("all_user_dict.pkl存储成功")
    lock.release()


@app.route('/getMode', methods=['GET'])
def get_mode():
    """
    获取当前对话模式
    :return:
    """
    check_session(session)
    if not check_user_bind(session):
        return "normal"
    user_info = get_user_info(session.get('user_id'))
    chat_id = user_info['selected_chat_id']
    chat_with_history = user_info['chats'][chat_id]['chat_with_history']
    if chat_with_history:
        return {"mode": "continuous"}
    else:
        return {"mode": "normal"}


@app.route('/changeMode/<status>', methods=['GET'])
def change_mode(status):
    """
    切换对话模式
    :return:
    """
    check_session(session)
    if not check_user_bind(session):
        return {"code": -1, "msg": "请先创建或输入已有用户id"}
    user_info = get_user_info(session.get('user_id'))
    chat_id = user_info['selected_chat_id']
    if status == "normal":
        user_info['chats'][chat_id]['chat_with_history'] = False
        print("开启普通对话")
        message = {"role": "system", "content": "切换至普通对话"}
    else:
        user_info['chats'][chat_id]['chat_with_history'] = True
        user_info['chats'][chat_id]['have_chat_context'] = 0
        print("开启连续对话")
        message = {"role": "system", "content": "切换至连续对话"}
    user_info['chats'][chat_id]['messages_history'].append(message)
    return {"code": 200, "data": message}


@app.route('/selectChat', methods=['GET'])
def select_chat():
    """
    选择聊天对象
    :return:
    """
    chat_id = request.args.get("id")
    check_session(session)
    if not check_user_bind(session):
        return {"code": -1, "msg": "请先创建或输入已有用户id"}
    user_id = session.get('user_id')
    user_info = get_user_info(user_id)
    user_info['selected_chat_id'] = chat_id
    return {"code": 200, "msg": "选择聊天对象成功"}


@app.route('/newChat', methods=['GET'])
def new_chat():
    """
    新建聊天对象
    :return:
    """
    name = request.args.get("name")
    time = request.args.get("time")
    check_session(session)
    if not check_user_bind(session):
        return {"code": -1, "msg": "请先创建或输入已有用户id"}
    user_id = session.get('user_id')
    user_info = get_user_info(user_id)
    new_chat_id = str(uuid.uuid1())
    user_info['selected_chat_id'] = new_chat_id
    user_info['chats'][new_chat_id] = new_chat_dict(user_id, name, time)
    print("新建聊天对象")
    return {"code": 200, "data": {"name": name, "id": new_chat_id, "selected": True, "messages_total": len(user_info['chats'][new_chat_id]['messages_history'])}}


@app.route('/deleteHistory', methods=['GET'])
def delete_history():
    """
    清空上下文
    :return:
    """
    check_session(session)
    if not check_user_bind(session):
        print("请先创建或输入已有用户id")
        return {"code": -1, "msg": "请先创建或输入已有用户id"}
    user_info = get_user_info(session.get('user_id'))
    chat_id = user_info['selected_chat_id']
    default_chat_id = user_info['default_chat_id']
    if default_chat_id == chat_id:
        print("清空历史记录")
        user_info["chats"][chat_id]['messages_history'] = user_info["chats"][chat_id]['messages_history'][:5]
    else:
        print("删除聊天对话")
        del user_info["chats"][chat_id]
    user_info['selected_chat_id'] = default_chat_id
    return "2"


def check_load_pickle():
    global all_user_dict

    if os.path.exists(USER_DICT_FILE):
        with open(USER_DICT_FILE, "rb") as pickle_file:
            all_user_dict = pickle.load(pickle_file)
            all_user_dict.change_capacity(USER_SAVE_MAX)
        print(f"已加载上次存储的用户上下文，共有{len(all_user_dict)}用户, 分别是")
        for i, user_id in enumerate(list(all_user_dict.keys())):
            print(f"{i} 用户id:{user_id}\t对话统计:\t", end="")
            user_info = all_user_dict.get(user_id)
            for chat_id in user_info['chats'].keys():
                print(f"{user_info['chats'][chat_id]['name']}[{len(user_info['chats'][chat_id]['messages_history'])}] ",
                      end="")
            print()
    elif os.path.exists("all_user_dict.pkl"):  # 适配当出现这个时
        print('检测到v1版本的上下文，将转换为v2版本')
        with open("all_user_dict.pkl", "rb") as pickle_file:
            all_user_dict = pickle.load(pickle_file)
            all_user_dict.change_capacity(USER_SAVE_MAX)
        print("共有用户", len(all_user_dict), "个")
        for user_id in list(all_user_dict.keys()):
            user_info: dict = all_user_dict.get(user_id)
            if "messages_history" in user_info:
                user_dict = new_user_dict(user_id, "")
                chat_id = user_dict['selected_chat_id']
                user_dict['chats'][chat_id]['messages_history'] = user_info['messages_history']
                user_dict['chats'][chat_id]['chat_with_history'] = user_info['chat_with_history']
                user_dict['chats'][chat_id]['have_chat_context'] = user_info['have_chat_context']
                all_user_dict.put(user_id, user_dict)  # 更新
        asyncio.run(save_all_user_dict())
    else:
        with open(USER_DICT_FILE, "wb") as pickle_file:
            pickle.dump(all_user_dict, pickle_file)
        print("未检测到上次存储的用户上下文，已创建新的用户上下文")

    # 判断all_user_dict是否为None且时LRUCache的对象
    if all_user_dict is None or not isinstance(all_user_dict, LRUCache):
        print("all_user_dict为空或不是LRUCache对象，已创建新的LRUCache对象")
        all_user_dict = LRUCache(USER_SAVE_MAX)


if __name__ == '__main__':
    print("持久化存储文件路径为:", os.path.join(os.getcwd(), USER_DICT_FILE))
    all_user_dict = LRUCache(USER_SAVE_MAX)
    check_load_pickle()

    if len(API_KEY) == 0:
        # 退出程序
        print("请在openai官网注册账号，获取api_key填写至程序内或命令行参数中")
        exit()
    app.run(host="0.0.0.0", port=PORT, debug=True)
