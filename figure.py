import pandas as pd
import matplotlib.pyplot as plt

def plot_logs_and_calculate_latency_jitter(file1, file2):
    # Đọc file log 1 (Publisher)
    df1 = pd.read_csv(file1, delimiter='\t')
    
    # Đọc file log 2 (Subscriber)
    df2 = pd.read_csv(file2, delimiter='\t')

    # Chuyển cột Timestamp thành kiểu datetime
    df1['Timestamp'] = pd.to_datetime(df1['Timestamp'], format='%H:%M:%S.%f')
    df2['Timestamp'] = pd.to_datetime(df2['Timestamp'], format='%H:%M:%S.%f')

    # Merge hai DataFrame dựa trên cột MessageID để tính độ trễ
    merged_df = pd.merge(df1, df2, on='MessageID', suffixes=('_pub', '_sub'))

    # Tính độ trễ (Subscriber Timestamp - Publisher Timestamp)
    merged_df['Latency'] = (merged_df['Timestamp_sub'] - merged_df['Timestamp_pub']).dt.total_seconds()

    # Tính độ trễ trung bình, lớn nhất, nhỏ nhất
    mean_latency = merged_df['Latency'].mean()
    max_latency = merged_df['Latency'].max()
    min_latency = merged_df['Latency'].min()

    print(f"Độ trễ trung bình: {mean_latency:.6f} giây")
    print(f"Độ trễ lớn nhất: {max_latency:.6f} giây")
    print(f"Độ trễ nhỏ nhất: {min_latency:.6f} giây")

    # Tính Jitter (sự chênh lệch độ trễ giữa các bản tin liên tiếp)
    merged_df['Jitter'] = merged_df['Latency'].diff().abs()

    # Tính jitter trung bình, lớn nhất, nhỏ nhất
    mean_jitter = merged_df['Jitter'].mean()
    max_jitter = merged_df['Jitter'].max()
    min_jitter = merged_df['Jitter'].min()

    print(f"Jitter trung bình: {mean_jitter:.6f} giây")
    print(f"Jitter lớn nhất: {max_jitter:.6f} giây")
    print(f"Jitter nhỏ nhất: {min_jitter:.6f} giây")

    # Vẽ biểu đồ trễ với các đường nối
    plt.figure(figsize=(10, 6))
    plt.plot(df1['MessageID'], df1['Timestamp'], color='blue', label='Publisher', marker='o')
    plt.plot(df2['MessageID'], df2['Timestamp'], color='red', label='Subscriber', marker='o')

    # Vẽ biểu đồ thời gian trễ
    plt.figure(figsize=(10, 6))
    plt.plot(merged_df['MessageID'], merged_df['Latency'], color='green', label='Latency (Subscriber - Publisher)', marker='o')
    
    # Đặt tiêu đề và nhãn cho biểu đồ trễ
    plt.title('Jitter on QOS 0 TLS')
    plt.xlabel('MessageID')
    plt.ylabel('Latency (seconds)')
    plt.legend()

    # Hiển thị biểu đồ đường trễ
    plt.show()

    # Vẽ biểu đồ cột cho độ trễ trung bình, lớn nhất, nhỏ nhất
    plt.figure(figsize=(8, 6))
    latency_values = [min_latency, mean_latency, max_latency]
    latency_labels = ['Min Latency', 'Avg Latency', 'Max Latency']
    plt.bar(latency_labels, latency_values, color=['blue', 'orange', 'red'])

    # Đặt tiêu đề và nhãn cho biểu đồ cột
    plt.title('Latency Statistics QOS 0 TLS')
    plt.ylabel('Latency (seconds)')
    plt.show()

    # Vẽ biểu đồ cột cho jitter trung bình, lớn nhất, nhỏ nhất
    plt.figure(figsize=(8, 6))
    jitter_values = [min_jitter, mean_jitter, max_jitter]
    jitter_labels = ['Min Jitter', 'Avg Jitter', 'Max Jitter']
    plt.bar(jitter_labels, jitter_values, color=['green', 'yellow', 'purple'])

    # Đặt tiêu đề và nhãn cho biểu đồ cột
    plt.title('Jitter Statistic QOS 0 TLS')
    plt.ylabel('Jitter (seconds)')
    plt.show()

    # Tìm MessageID có trong Publisher nhưng không có trong Subscriber
    missing_in_sub = df1[~df1['MessageID'].isin(df2['MessageID'])]

    # Hiển thị các dòng MessageID và Payload mà không có trong Subscriber
    if not missing_in_sub.empty:
        print("Các dòng MessageID và Payload có trong Publisher nhưng không có trong Subscriber:")
        print(missing_in_sub[['MessageID', 'Payload']])
    else:
        print("Tất cả MessageID từ Publisher đều có trong Subscriber.")

# Gọi hàm với đường dẫn đến các file log
plot_logs_and_calculate_latency_jitter('publisher_log_qos0_tls.txt', 'subscriber_log_qos0_tls.txt')
