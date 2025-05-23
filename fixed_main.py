# 修复后的main函数 - 语法错误已修复
def main():
    """主处理流程"""
    # 解析命令行参数
    import argparse
    parser = argparse.ArgumentParser(description='处理N16 PCAP文件中的HTTP/2帧')
    parser.add_argument('-i', '--input', dest='input_file', default="pcap/N16_create_16p.pcap",
                       help='输入PCAP文件路径')
    parser.add_argument('-o', '--output', dest='output_file', default="pcap/N16_1504.pcap",
                       help='输出PCAP文件路径')
    
    args = parser.parse_args()
    
    # 输入输出文件路径
    PCAP_IN = args.input_file
    PCAP_OUT = args.output_file
    
    logger.info(f"开始处理文件 {PCAP_IN}")
    if not os.path.exists(PCAP_IN):
        logger.error(f"输入文件不存在: {PCAP_IN}")
        return
    
    packets = rdpcap(PCAP_IN)
    modified_packets = []
    logger.info(f"共读取到 {len(packets)} 个报文")
    
    seq_diff = {}
    
    # 记录需要特殊处理的报文序号（从1开始）
    target_pkts = {9, 11, 13, 15}
    
    for idx, pkt in enumerate(packets, 1):
        modified = False
        original_length = None
        new_length = None
        
        logger.debug(f"处理第{idx}个报文")
        
        # 对第15号报文使用专用处理逻辑
        if idx == 15 and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            logger.info(f"对第15号报文使用专用处理函数")
            original_length = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
            
            # 先尝试直接二进制替换（但不修改content-length）
            apply_direct_binary_replacements(pkt, idx)
            
            # 使用专门的处理函数
            if process_packet15(pkt):
                new_length = len(pkt[Raw].load)
                modified = True
                logger.info(f"第15号报文专用处理成功，原长度：{original_length}，新长度：{new_length}")
                
                # 处理IP和序列号
                process_packet(pkt, seq_diff, IP_REPLACEMENTS, original_length, new_length)
                modified_packets.append(pkt)
                continue  # 跳过常规处理
            else:
                logger.warning("第15号报文专用处理失败，回退到常规处理")
        
        # 处理其他目标报文
        elif idx in target_pkts and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            logger.info(f"特殊处理第{idx}个报文")
            
            # 初始化数据结构
            content_length_frames = []
            data_frames = []
            
            # 先尝试直接在原始负载上进行二进制替换（第一阶段）
            direct_modified = apply_direct_binary_replacements(pkt, idx)
            
            # 处理HTTP/2帧
            try:
                # 获取可能已修改的原始负载
                raw = bytes(pkt[Raw].load)
                
                # 提取所有帧
                frames = extract_frames(raw)
                if not frames:
                    logger.warning(f"第{idx}个报文未找到有效HTTP/2帧")
                else:
                    # 第一轮：查找所有关键帧
                    for frame_idx, (frame_header, frame_type, frame_data, start_offset, end_offset) in enumerate(frames):
                        if frame_type == 0x1:  # HEADERS帧
                            # 检查是否包含content-length字段
                            if b'content-length' in frame_data.lower() or b'Content-Length' in frame_data:
                                content_length_frames.append(frame_idx)
                        elif frame_type == 0x0:  # DATA帧
                            data_frames.append(frame_idx)
                    
                    # 第二轮：处理DATA和content-length
                    if data_frames:
                        for data_idx in data_frames:
                            frame_header, frame_type, frame_data, start_offset, end_offset = frames[data_idx]
                            new_data = process_http2_data_frame(frame_data)
                            if new_data is not None and new_data != frame_data:
                                modified = True
                                new_data_len = len(new_data)
                                logger.info(f"第{idx}个报文DATA帧已修改，新长度: {new_data_len}")
                                
                                # 更新帧数据
                                frame_header.length = new_data_len
                                frames[data_idx] = (frame_header, frame_type, new_data, start_offset, start_offset + 9 + new_data_len)
                                
                                # 更新content-length
                                if content_length_frames:
                                    for cl_idx in content_length_frames:
                                        cl_header, cl_type, cl_data, cl_start, cl_end = frames[cl_idx]
                                        new_cl_data = update_content_length(cl_data, new_data_len)
                                        if new_cl_data != cl_data:
                                            cl_header.length = len(new_cl_data)
                                            frames[cl_idx] = (cl_header, cl_type, new_cl_data, cl_start, cl_start + 9 + len(new_cl_data))
                    
                    # 重建payload
                    if modified:
                        new_payload = b''
                        for frame_header, frame_type, frame_data, _, _ in frames:
                            new_payload += frame_header.build() + frame_data
                        
                        # 更新报文
                        original_length = len(raw)
                        new_length = len(new_payload)
                        pkt[Raw].load = new_payload
            except Exception as e:
                logger.error(f"处理第{idx}个报文错误: {str(e)}")
                import traceback
                logger.error(traceback.format_exc())
        
        # 处理所有报文的IP和序列号
        process_packet(pkt, seq_diff, IP_REPLACEMENTS, original_length, new_length)
        modified_packets.append(pkt)
    
    logger.info(f"保存修改后的PCAP到 {PCAP_OUT}")
    wrpcap(PCAP_OUT, modified_packets)
    logger.info(f"处理完成，共处理 {len(packets)} 个报文")

if __name__ == "__main__":
    main()
