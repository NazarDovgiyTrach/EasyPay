--
-- PostgreSQL database dump
--

-- Dumped from database version 10.5
-- Dumped by pg_dump version 10.5

-- Started on 2018-09-04 17:47:54



--
-- TOC entry 3044 (class 0 OID 21766)
-- Dependencies: 229
-- Data for Name: region; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.region (id, name) VALUES (1, 'Чернівецька область');
INSERT INTO public.region (id, name) VALUES (2, 'Дніпропетровська область');


--
-- TOC entry 3033 (class 0 OID 21711)
-- Dependencies: 218
-- Data for Name: city; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.city (id, name, region_id) VALUES (1, 'Чернівці', 1);
INSERT INTO public.city (id, name, region_id) VALUES (3, 'Кривий Ріг', 2);


--
-- TOC entry 3047 (class 0 OID 21784)
-- Dependencies: 232
-- Data for Name: street; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.street (id, name, city_id) VALUES (2, 'проспект Незалежності', 1);
INSERT INTO public.street (id, name, city_id) VALUES (4, 'вулиця Ватутіна', 3);
INSERT INTO public.street (id, name, city_id) VALUES (5, 'вулиця Винниченка', 1);
INSERT INTO public.street (id, name, city_id) VALUES (6, 'вулиця Поштова', 1);
INSERT INTO public.street (id, name, city_id) VALUES (7, 'вулиця Гагаріна', 1);
INSERT INTO public.street (id, name, city_id) VALUES (8, 'вулиця Толстого', 1);
INSERT INTO public.street (id, name, city_id) VALUES (9, 'вулиця Горького', 1);
INSERT INTO public.street (id, name, city_id) VALUES (10, 'вулиця Сковороди', 1);
INSERT INTO public.street (id, name, city_id) VALUES (11, 'вулиця Університетська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (12, 'вулиця Лисенка', 1);
INSERT INTO public.street (id, name, city_id) VALUES (13, 'вулиця Глінки', 1);
INSERT INTO public.street (id, name, city_id) VALUES (14, 'вулиця Котляревського', 1);
INSERT INTO public.street (id, name, city_id) VALUES (15, 'вулиця Нагірна', 1);
INSERT INTO public.street (id, name, city_id) VALUES (16, 'Кафедральна вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (17, 'вулиця Шевченка', 1);
INSERT INTO public.street (id, name, city_id) VALUES (18, 'вулиця Пушкіна', 1);
INSERT INTO public.street (id, name, city_id) VALUES (19, 'вулиця Маяковського', 1);
INSERT INTO public.street (id, name, city_id) VALUES (20, 'вулиця Тобілевича', 1);
INSERT INTO public.street (id, name, city_id) VALUES (21, 'вулиця Козачука', 1);
INSERT INTO public.street (id, name, city_id) VALUES (22, 'вулиця Ольжича', 1);
INSERT INTO public.street (id, name, city_id) VALUES (23, 'вулиця Кошового', 1);
INSERT INTO public.street (id, name, city_id) VALUES (24, 'вулиця Сторожинецька', 1);
INSERT INTO public.street (id, name, city_id) VALUES (25, 'вулиця Горіхівська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (26, 'вулиця Каспрука', 1);
INSERT INTO public.street (id, name, city_id) VALUES (27, 'вулиця Шухевича', 1);
INSERT INTO public.street (id, name, city_id) VALUES (28, 'вулиця Рівненська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (29, 'вулиця Мукачівська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (30, 'вулиця Прилуцька', 1);
INSERT INTO public.street (id, name, city_id) VALUES (31, 'вулиця Ковельська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (32, 'вулиця Хотинська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (33, 'вулиця Хрещатинська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (34, 'вулиця Путилівська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (35, 'вулиця Ставчанська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (36, 'вулиця Мартовича', 1);
INSERT INTO public.street (id, name, city_id) VALUES (37, 'вулиця Дзержика', 1);
INSERT INTO public.street (id, name, city_id) VALUES (38, 'вулиця Вашківська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (39, 'вулиця Комунальників', 1);
INSERT INTO public.street (id, name, city_id) VALUES (40, 'вулиця Руська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (41, 'Трипільська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (42, 'Роменська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (43, 'Петрозаводська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (44, 'Висока вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (45, 'Немирівська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (46, 'Кадіївська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (47, 'Алтайська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (48, 'Уральська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (49, 'Барнаульська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (50, 'Сімферопольська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (51, 'вулиця Нечая', 1);
INSERT INTO public.street (id, name, city_id) VALUES (52, 'вулиця Київська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (53, 'Заставнянська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (54, 'вулиця Весняна', 1);
INSERT INTO public.street (id, name, city_id) VALUES (55, 'вулиця Ходорівська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (56, 'вулиця Стрийська', 1);
INSERT INTO public.street (id, name, city_id) VALUES (57, 'вулиця Маковея', 1);
INSERT INTO public.street (id, name, city_id) VALUES (58, 'вулиця Вербова', 1);
INSERT INTO public.street (id, name, city_id) VALUES (59, 'Бузкова вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (60, 'Ясенева вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (61, 'Фіалкова вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (62, 'Берегометська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (63, 'Ленківська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (64, 'Банилівська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (65, 'Іркутська вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (66, 'Калузька вулиця', 1);
INSERT INTO public.street (id, name, city_id) VALUES (67, 'Снятинська вулиця', 1);


--
-- TOC entry 3038 (class 0 OID 21736)
-- Dependencies: 223
-- Data for Name: house; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.house (id, number, street_id) VALUES (1, '131', 2);
INSERT INTO public.house (id, number, street_id) VALUES (2, '18', 4);
INSERT INTO public.house (id, number, street_id) VALUES (3, '3', 5);
INSERT INTO public.house (id, number, street_id) VALUES (4, '1', 6);
INSERT INTO public.house (id, number, street_id) VALUES (5, '4', 7);
INSERT INTO public.house (id, number, street_id) VALUES (6, '2', 8);
INSERT INTO public.house (id, number, street_id) VALUES (7, '12', 9);
INSERT INTO public.house (id, number, street_id) VALUES (8, '43', 10);
INSERT INTO public.house (id, number, street_id) VALUES (9, '2', 11);
INSERT INTO public.house (id, number, street_id) VALUES (10, '4', 12);
INSERT INTO public.house (id, number, street_id) VALUES (11, '2', 13);
INSERT INTO public.house (id, number, street_id) VALUES (12, '10', 14);
INSERT INTO public.house (id, number, street_id) VALUES (13, '5', 15);
INSERT INTO public.house (id, number, street_id) VALUES (14, '1', 16);
INSERT INTO public.house (id, number, street_id) VALUES (15, '44', 17);
INSERT INTO public.house (id, number, street_id) VALUES (16, '12', 18);
INSERT INTO public.house (id, number, street_id) VALUES (17, '16', 19);
INSERT INTO public.house (id, number, street_id) VALUES (18, '12', 20);
INSERT INTO public.house (id, number, street_id) VALUES (19, '12', 21);
INSERT INTO public.house (id, number, street_id) VALUES (20, '10', 22);
INSERT INTO public.house (id, number, street_id) VALUES (21, '2', 23);
INSERT INTO public.house (id, number, street_id) VALUES (22, '100', 24);
INSERT INTO public.house (id, number, street_id) VALUES (23, '100', 25);
INSERT INTO public.house (id, number, street_id) VALUES (24, '12', 26);
INSERT INTO public.house (id, number, street_id) VALUES (25, '2', 27);
INSERT INTO public.house (id, number, street_id) VALUES (26, '5', 28);
INSERT INTO public.house (id, number, street_id) VALUES (27, '25', 29);
INSERT INTO public.house (id, number, street_id) VALUES (28, '44', 30);
INSERT INTO public.house (id, number, street_id) VALUES (29, '1', 31);
INSERT INTO public.house (id, number, street_id) VALUES (30, '49', 32);
INSERT INTO public.house (id, number, street_id) VALUES (31, '15', 33);
INSERT INTO public.house (id, number, street_id) VALUES (32, '16', 34);
INSERT INTO public.house (id, number, street_id) VALUES (33, '12', 35);
INSERT INTO public.house (id, number, street_id) VALUES (34, '67', 36);
INSERT INTO public.house (id, number, street_id) VALUES (35, '60', 25);
INSERT INTO public.house (id, number, street_id) VALUES (36, '6', 37);
INSERT INTO public.house (id, number, street_id) VALUES (37, '1', 38);
INSERT INTO public.house (id, number, street_id) VALUES (38, '2', 39);
INSERT INTO public.house (id, number, street_id) VALUES (39, '241', 40);
INSERT INTO public.house (id, number, street_id) VALUES (40, '243', 40);
INSERT INTO public.house (id, number, street_id) VALUES (41, '279', 40);
INSERT INTO public.house (id, number, street_id) VALUES (42, '50', 5);
INSERT INTO public.house (id, number, street_id) VALUES (43, '1', 41);
INSERT INTO public.house (id, number, street_id) VALUES (44, '12', 42);
INSERT INTO public.house (id, number, street_id) VALUES (45, '2', 43);
INSERT INTO public.house (id, number, street_id) VALUES (46, '12', 44);
INSERT INTO public.house (id, number, street_id) VALUES (47, '1', 45);
INSERT INTO public.house (id, number, street_id) VALUES (48, '12', 46);
INSERT INTO public.house (id, number, street_id) VALUES (49, '1', 47);
INSERT INTO public.house (id, number, street_id) VALUES (50, '2', 48);
INSERT INTO public.house (id, number, street_id) VALUES (51, '6', 49);
INSERT INTO public.house (id, number, street_id) VALUES (52, '100', 50);
INSERT INTO public.house (id, number, street_id) VALUES (53, '12', 51);
INSERT INTO public.house (id, number, street_id) VALUES (54, '100', 52);
INSERT INTO public.house (id, number, street_id) VALUES (55, '120', 52);
INSERT INTO public.house (id, number, street_id) VALUES (56, '150', 52);
INSERT INTO public.house (id, number, street_id) VALUES (57, '10', 53);
INSERT INTO public.house (id, number, street_id) VALUES (58, '96', 54);
INSERT INTO public.house (id, number, street_id) VALUES (59, '12', 55);
INSERT INTO public.house (id, number, street_id) VALUES (60, '15', 56);
INSERT INTO public.house (id, number, street_id) VALUES (61, '98', 57);
INSERT INTO public.house (id, number, street_id) VALUES (62, '12', 58);
INSERT INTO public.house (id, number, street_id) VALUES (63, '12', 59);
INSERT INTO public.house (id, number, street_id) VALUES (64, '16', 60);
INSERT INTO public.house (id, number, street_id) VALUES (65, '1', 61);
INSERT INTO public.house (id, number, street_id) VALUES (66, '1', 62);
INSERT INTO public.house (id, number, street_id) VALUES (67, '12', 63);
INSERT INTO public.house (id, number, street_id) VALUES (68, '100', 64);
INSERT INTO public.house (id, number, street_id) VALUES (69, '100', 65);
INSERT INTO public.house (id, number, street_id) VALUES (70, '1', 66);
INSERT INTO public.house (id, number, street_id) VALUES (71, '1', 67);


--
-- TOC entry 3037 (class 0 OID 21731)
-- Dependencies: 222
-- Data for Name: flat; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.flat (id, number, house_id) VALUES (1, '', 1);
INSERT INTO public.flat (id, number, house_id) VALUES (2, '', 2);
INSERT INTO public.flat (id, number, house_id) VALUES (3, '', 3);
INSERT INTO public.flat (id, number, house_id) VALUES (4, '24', 4);
INSERT INTO public.flat (id, number, house_id) VALUES (5, '123', 5);
INSERT INTO public.flat (id, number, house_id) VALUES (6, '', 6);
INSERT INTO public.flat (id, number, house_id) VALUES (7, '23', 7);
INSERT INTO public.flat (id, number, house_id) VALUES (8, '65', 8);
INSERT INTO public.flat (id, number, house_id) VALUES (9, '5', 9);
INSERT INTO public.flat (id, number, house_id) VALUES (10, '15', 10);
INSERT INTO public.flat (id, number, house_id) VALUES (11, '', 11);
INSERT INTO public.flat (id, number, house_id) VALUES (12, '', 12);
INSERT INTO public.flat (id, number, house_id) VALUES (13, '', 13);
INSERT INTO public.flat (id, number, house_id) VALUES (14, '', 14);
INSERT INTO public.flat (id, number, house_id) VALUES (15, '54', 15);
INSERT INTO public.flat (id, number, house_id) VALUES (16, '', 16);
INSERT INTO public.flat (id, number, house_id) VALUES (17, '24', 17);
INSERT INTO public.flat (id, number, house_id) VALUES (18, '', 18);
INSERT INTO public.flat (id, number, house_id) VALUES (19, '', 19);
INSERT INTO public.flat (id, number, house_id) VALUES (20, '', 20);
INSERT INTO public.flat (id, number, house_id) VALUES (21, '', 21);
INSERT INTO public.flat (id, number, house_id) VALUES (22, '', 22);
INSERT INTO public.flat (id, number, house_id) VALUES (23, '2', 23);
INSERT INTO public.flat (id, number, house_id) VALUES (24, '', 24);
INSERT INTO public.flat (id, number, house_id) VALUES (25, '25', 25);
INSERT INTO public.flat (id, number, house_id) VALUES (26, '5', 26);
INSERT INTO public.flat (id, number, house_id) VALUES (27, '', 27);
INSERT INTO public.flat (id, number, house_id) VALUES (28, '12', 28);
INSERT INTO public.flat (id, number, house_id) VALUES (29, '', 29);
INSERT INTO public.flat (id, number, house_id) VALUES (30, '33', 30);
INSERT INTO public.flat (id, number, house_id) VALUES (31, '12', 31);
INSERT INTO public.flat (id, number, house_id) VALUES (32, '12', 32);
INSERT INTO public.flat (id, number, house_id) VALUES (33, '12', 33);
INSERT INTO public.flat (id, number, house_id) VALUES (34, '', 34);
INSERT INTO public.flat (id, number, house_id) VALUES (35, '', 35);
INSERT INTO public.flat (id, number, house_id) VALUES (36, '12', 36);
INSERT INTO public.flat (id, number, house_id) VALUES (37, '', 37);
INSERT INTO public.flat (id, number, house_id) VALUES (38, '', 38);
INSERT INTO public.flat (id, number, house_id) VALUES (39, '245', 39);
INSERT INTO public.flat (id, number, house_id) VALUES (40, '100', 40);
INSERT INTO public.flat (id, number, house_id) VALUES (41, '100', 41);
INSERT INTO public.flat (id, number, house_id) VALUES (42, '1', 42);
INSERT INTO public.flat (id, number, house_id) VALUES (43, '', 43);
INSERT INTO public.flat (id, number, house_id) VALUES (44, '', 44);
INSERT INTO public.flat (id, number, house_id) VALUES (45, '', 45);
INSERT INTO public.flat (id, number, house_id) VALUES (46, '2', 46);
INSERT INTO public.flat (id, number, house_id) VALUES (47, '2', 47);
INSERT INTO public.flat (id, number, house_id) VALUES (48, '12', 48);
INSERT INTO public.flat (id, number, house_id) VALUES (49, '1', 49);
INSERT INTO public.flat (id, number, house_id) VALUES (50, '12', 50);
INSERT INTO public.flat (id, number, house_id) VALUES (51, '12', 51);
INSERT INTO public.flat (id, number, house_id) VALUES (52, '100', 52);
INSERT INTO public.flat (id, number, house_id) VALUES (53, '1', 53);
INSERT INTO public.flat (id, number, house_id) VALUES (54, '', 54);
INSERT INTO public.flat (id, number, house_id) VALUES (55, '', 55);
INSERT INTO public.flat (id, number, house_id) VALUES (56, '5', 56);
INSERT INTO public.flat (id, number, house_id) VALUES (57, '', 57);
INSERT INTO public.flat (id, number, house_id) VALUES (58, '', 58);
INSERT INTO public.flat (id, number, house_id) VALUES (59, '67', 59);
INSERT INTO public.flat (id, number, house_id) VALUES (60, '45', 60);
INSERT INTO public.flat (id, number, house_id) VALUES (61, '', 61);
INSERT INTO public.flat (id, number, house_id) VALUES (62, '231', 62);
INSERT INTO public.flat (id, number, house_id) VALUES (63, '23', 63);
INSERT INTO public.flat (id, number, house_id) VALUES (64, '123', 64);
INSERT INTO public.flat (id, number, house_id) VALUES (65, '123', 65);
INSERT INTO public.flat (id, number, house_id) VALUES (66, '1', 66);
INSERT INTO public.flat (id, number, house_id) VALUES (67, '', 67);
INSERT INTO public.flat (id, number, house_id) VALUES (68, '', 68);
INSERT INTO public.flat (id, number, house_id) VALUES (69, '100', 69);
INSERT INTO public.flat (id, number, house_id) VALUES (70, '1', 70);
INSERT INTO public.flat (id, number, house_id) VALUES (71, '123', 71);


--
-- TOC entry 3032 (class 0 OID 21706)
-- Dependencies: 217
-- Data for Name: addresses; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (1, true, 48.2690871, 25.924404099999947, 1, 1, 1, 1, 2);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (2, true, 48.025148000000002, 33.469425099999967, 3, 2, 2, 2, 4);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (3, true, 48.2708972, 25.953113400000007, 1, 3, 3, 1, 5);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (4, true, 48.293169499999998, 25.934576099999958, 1, 4, 4, 1, 6);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (5, true, 48.297532199999999, 25.936605999999983, 1, 5, 5, 1, 7);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (6, true, 48.295348099999998, 25.934265600000003, 1, 6, 6, 1, 8);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (7, true, 48.295746200000004, 25.93277850000004, 1, 7, 7, 1, 9);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (8, true, 48.292247599999989, 25.928941000000009, 1, 8, 8, 1, 10);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (9, true, 48.292825800000003, 25.934579600000006, 1, 9, 9, 1, 11);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (10, true, 48.2921671, 25.930448399999932, 1, 10, 10, 1, 12);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (11, true, 48.289922300000008, 25.929384600000049, 1, 11, 11, 1, 13);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (12, true, 48.289083000000012, 25.931894400000033, 1, 12, 12, 1, 14);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (13, true, 48.287550799999998, 25.930330000000026, 1, 13, 13, 1, 15);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (14, true, 48.287074999999987, 25.935322700000029, 1, 14, 14, 1, 16);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (15, true, 48.286315300000012, 25.94225890000007, 1, 15, 15, 1, 17);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (16, true, 48.288062099999998, 25.942760200000066, 1, 16, 16, 1, 18);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (17, true, 48.289479200000002, 25.943222200000037, 1, 17, 17, 1, 19);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (18, true, 48.285018000000001, 25.941299000000072, 1, 18, 18, 1, 20);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (19, true, 48.286411000000001, 25.94714010000007, 1, 19, 19, 1, 21);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (20, true, 48.286717900000014, 25.945527599999991, 1, 20, 20, 1, 22);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (21, true, 48.276790699999999, 25.928110999999944, 1, 21, 21, 1, 23);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (22, true, 48.273249399999997, 25.918623600000046, 1, 22, 22, 1, 24);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (23, true, 48.292853500000007, 25.882487500000025, 1, 23, 23, 1, 25);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (24, true, 48.274142899999987, 25.923390599999948, 1, 24, 24, 1, 26);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (25, true, 48.269552300000001, 25.922298500000011, 1, 25, 25, 1, 27);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (26, true, 48.2648169, 25.921831699999984, 1, 26, 26, 1, 28);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (27, true, 48.274748000000002, 25.908476199999996, 1, 27, 27, 1, 29);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (28, true, 48.270911899999987, 25.909399699999994, 1, 28, 28, 1, 30);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (29, true, 48.273966999999999, 25.918696700000055, 1, 29, 29, 1, 31);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (30, true, 48.319228300000013, 25.937909900000022, 1, 30, 30, 1, 32);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (31, true, 48.273651399999999, 25.903132000000028, 1, 31, 31, 1, 33);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (32, true, 48.269014100000007, 25.892609399999969, 1, 32, 32, 1, 34);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (33, true, 48.274174599999988, 25.901473300000021, 1, 33, 33, 1, 35);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (34, true, 48.2810129, 25.90351140000007, 1, 34, 34, 1, 36);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (35, true, 48.286926999999999, 25.89313889999994, 1, 35, 35, 1, 25);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (36, true, 48.285761299999997, 25.925108000000023, 1, 36, 36, 1, 37);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (37, true, 48.2855609, 25.890957100000037, 1, 37, 37, 1, 38);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (38, true, 48.267313299999998, 25.991444999999999, 1, 38, 38, 1, 39);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (39, true, 48.277454000000013, 25.98526430000004, 1, 39, 39, 1, 40);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (40, true, 48.277197600000001, 25.986151199999995, 1, 40, 40, 1, 40);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (41, true, 48.27131, 25.997746000000006, 1, 41, 41, 1, 40);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (42, true, 48.272287499999997, 25.956730900000025, 1, 42, 42, 1, 5);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (43, true, 48.278668499999988, 25.994582100000002, 1, 43, 43, 1, 41);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (44, true, 48.282086600000007, 25.993894599999976, 1, 44, 44, 1, 42);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (45, true, 48.283595400000003, 25.99372859999994, 1, 45, 45, 1, 43);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (46, true, 48.279629800000002, 25.988621700000067, 1, 46, 46, 1, 44);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (47, true, 48.273508399999997, 25.982285400000023, 1, 47, 47, 1, 45);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (48, true, 48.2774912, 26.003448599999956, 1, 48, 48, 1, 46);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (49, true, 48.275241000000008, 26.003593099999989, 1, 49, 49, 1, 47);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (50, true, 48.273760699999997, 26.006154700000025, 1, 50, 50, 1, 48);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (51, true, 48.284370600000003, 26.002123399999959, 1, 51, 51, 1, 49);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (52, true, 48.286458799999998, 25.992062400000009, 1, 52, 52, 1, 50);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (53, true, 48.286969999999997, 25.986776299999974, 1, 53, 53, 1, 51);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (54, true, 48.285572299999998, 25.913932799999998, 1, 54, 54, 1, 52);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (55, true, 48.285572299999998, 25.913932799999998, 1, 55, 55, 1, 52);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (56, true, 48.287511299999998, 25.920411699999931, 1, 56, 56, 1, 52);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (57, true, 48.288145399999998, 25.913368699999978, 1, 57, 57, 1, 53);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (58, true, 48.293660199999998, 25.900499599999989, 1, 58, 58, 1, 54);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (59, true, 48.295296, 25.911281400000007, 1, 59, 59, 1, 55);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (60, true, 48.294160699999999, 25.918698100000029, 1, 60, 60, 1, 56);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (61, true, 48.297653500000003, 25.910110700000018, 1, 61, 61, 1, 57);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (62, true, 48.294730999999999, 25.886551499999996, 1, 62, 62, 1, 58);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (63, true, 48.295062899999998, 25.889418400000068, 1, 63, 63, 1, 59);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (64, true, 48.296506899999997, 25.886763599999995, 1, 64, 64, 1, 60);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (65, true, 48.296917800000003, 25.884620100000006, 1, 65, 65, 1, 61);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (66, true, 48.295029000000007, 25.882172800000035, 1, 66, 66, 1, 62);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (67, true, 48.290248499999997, 25.88719500000002, 1, 67, 67, 1, 63);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (68, true, 48.291910799999997, 25.893441700000039, 1, 68, 68, 1, 64);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (69, true, 48.297055299999997, 25.902250399999957, 1, 69, 69, 1, 65);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (70, true, 48.299855999999998, 25.900926799999979, 1, 70, 70, 1, 66);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (71, true, 48.3004526, 25.903225600000042, 1, 71, 71, 1, 67);


--
-- TOC entry 3050 (class 0 OID 21799)
-- Dependencies: 235
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (107, NULL, '', 'manager3@gmail.com', NULL, 'Andriy', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'MANAGER', 'Zagarovskiy', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (108, NULL, '', 'manager4@gmail.com', NULL, 'Viktoriya', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'MANAGER', 'Radashko', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (111, NULL, '', 'inspector3@gmail.com', NULL, 'Olga', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'INSPECTOR', 'Ivanova', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (112, NULL, '', 'inspector4@gmail.com', NULL, 'Volodimir', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'INSPECTOR', 'Golovach', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (100, NULL, '', 'admin1@gmail.com', '2018-09-04', 'Ivan', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'ADMIN', 'Petrov', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (101, NULL, '', 'user1@gmail.com', '2018-09-04', 'Mariya', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'USER', 'Chuikina', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (110, NULL, '', 'inspector2@gmail.com', '2018-09-04', 'Makar', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'INSPECTOR', 'Portnov', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (105, NULL, '', 'manager1@gmail.com', '2018-09-04', 'Viktor', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'MANAGER', 'Volchinskiy', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (106, NULL, '', 'manager2@gmail.com', '2018-09-04', 'Ilya', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'MANAGER', 'Sherbunchak', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (102, NULL, '', 'user2@gmail.com', '2018-09-04', 'Valera', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780812', 'USER', 'Dobkin', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (103, NULL, '', 'user3@gmail.com', '2018-09-04', 'Pavel', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780812', 'USER', 'Chernov', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (104, NULL, '', 'user4@gmail.com', '2018-09-04', 'Germiona', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780812', 'USER', 'Potter', 'ACTIVE');
INSERT INTO public.users (user_id, stripecustomerid, avatar, email, last_login, name, password, phone_number, role, surname, status) VALUES (109, NULL, '', 'inspector1@gmail.com', '2018-09-04', 'Oleg', '$2a$10$80qxcLmmY3l2DNAS08CeWusfSr/uS1mvt3zBQKSih0fiMwZiEACxS', '+380968780876', 'INSPECTOR', 'Adamov', 'ACTIVE');


--
-- TOC entry 3051 (class 0 OID 21807)
-- Dependencies: 236
-- Data for Name: utilities; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.utilities (id, is_active, identification_code, logo, name, phone, web_site, address_id, user_id) VALUES (3, true, '01124343255673', NULL, 'Pat "Chernivtsihaz"', '+380 372 549 004', 'https://cv.104.ua/', 3, 106);
INSERT INTO public.utilities (id, is_active, identification_code, logo, name, phone, web_site, address_id, user_id) VALUES (2, true, '12345678', NULL, 'ДнепрОблЭнерго', '+380 564 046 365', 'http://doe.com.ua/', 2, 105);


--
-- TOC entry 3035 (class 0 OID 21721)
-- Dependencies: 220
-- Data for Name: debts; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (1, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (2, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (3, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (4, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (5, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (6, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (7, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (8, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (9, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (10, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (11, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (12, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (13, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (14, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (16, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (17, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (18, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (19, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (20, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (21, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (22, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (23, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (24, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (25, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (26, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (27, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (28, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (29, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (30, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (31, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (32, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (33, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (34, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (35, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (36, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (37, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (38, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (39, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (40, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (41, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (42, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (43, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (44, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (45, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (46, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (47, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (48, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (49, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (50, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (51, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (52, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (53, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (54, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (55, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (56, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (57, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (58, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (59, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (60, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (61, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (62, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (63, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (64, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (65, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (66, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (67, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (68, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (69, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (70, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (71, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (72, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (73, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (74, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (75, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (76, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (77, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (78, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (79, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (80, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (81, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (82, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (83, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (84, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (85, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (86, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (87, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (88, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (89, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (90, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (91, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (92, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (93, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (94, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (95, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (96, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (97, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (98, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (99, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (100, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (101, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (102, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (103, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (104, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (105, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (106, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (107, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (108, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (109, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (110, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (111, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (112, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (113, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (114, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (115, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (116, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (117, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (118, NULL, NULL, NULL, 0, 2);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (119, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (120, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (121, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (122, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (123, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (124, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (125, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (126, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (127, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (128, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (129, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (130, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (131, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (132, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (133, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (134, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (135, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (136, NULL, NULL, NULL, 0, 3);
INSERT INTO public.debts (id, last_counter_reminder_send, last_debt_reminder_send, last_paid, value, utility_id) VALUES (15, NULL, NULL, '2018-09-04', -4.5999999999999996, 2);


--
-- TOC entry 3034 (class 0 OID 21716)
-- Dependencies: 219
-- Data for Name: counters; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (37, true, 15, false, '2018-09-04', 15, 11, 15, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (80, true, 1, false, NULL, 1, 36, 37, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (276, true, 1, false, NULL, 1, 70, 135, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (277, true, 1, false, NULL, 1, 70, 135, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (278, true, 1, false, NULL, 1, 71, 136, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (279, true, 1, false, NULL, 1, 71, 136, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (272, true, 1, false, NULL, 1, 68, 133, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (273, true, 1, false, NULL, 1, 68, 133, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (274, true, 1, false, NULL, 1, 69, 134, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (275, true, 1, false, NULL, 1, 69, 134, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (268, true, 1, false, NULL, 1, 66, 131, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (269, true, 1, false, NULL, 1, 66, 131, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (270, true, 1, false, NULL, 1, 67, 132, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (271, true, 1, false, NULL, 1, 67, 132, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (264, true, 1, false, NULL, 1, 64, 129, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (265, true, 1, false, NULL, 1, 64, 129, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (266, true, 1, false, NULL, 1, 65, 130, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (267, true, 1, false, NULL, 1, 65, 130, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (260, true, 1, false, NULL, 1, 62, 127, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (261, true, 1, false, NULL, 1, 62, 127, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (262, true, 1, false, NULL, 1, 63, 128, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (263, true, 1, false, NULL, 1, 63, 128, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (256, true, 1, false, NULL, 1, 60, 125, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (257, true, 1, false, NULL, 1, 60, 125, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (258, true, 1, false, NULL, 1, 61, 126, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (259, true, 1, false, NULL, 1, 61, 126, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (92, true, 1, false, NULL, 1, 33, 43, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (93, true, 1, false, NULL, 1, 33, 43, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (94, true, 1, false, NULL, 1, 33, 44, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (95, true, 1, false, NULL, 1, 33, 44, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (88, true, 1, false, NULL, 1, 34, 41, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (89, true, 1, false, NULL, 1, 34, 41, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (90, true, 1, false, NULL, 1, 34, 42, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (91, true, 1, false, NULL, 1, 34, 42, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (84, true, 1, false, NULL, 1, 35, 39, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (85, true, 1, false, NULL, 1, 35, 39, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (86, true, 1, false, NULL, 1, 35, 40, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (87, true, 1, false, NULL, 1, 35, 40, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (81, true, 1, false, NULL, 1, 36, 37, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (82, true, 1, false, NULL, 1, 36, 38, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (83, true, 1, false, NULL, 1, 36, 38, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (76, true, 1, false, NULL, 1, 37, 35, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (77, true, 1, false, NULL, 1, 37, 35, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (78, true, 1, false, NULL, 1, 37, 36, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (79, true, 1, false, NULL, 1, 37, 36, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (72, true, 1, false, NULL, 1, 20, 33, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (73, true, 1, false, NULL, 1, 20, 33, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (74, true, 1, false, NULL, 1, 20, 34, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (75, true, 1, false, NULL, 1, 20, 34, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (68, true, 1, false, NULL, 1, 19, 31, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (69, true, 1, false, NULL, 1, 19, 31, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (70, true, 1, false, NULL, 1, 19, 32, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (71, true, 1, false, NULL, 1, 19, 32, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (64, true, 1, false, NULL, 1, 18, 29, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (65, true, 1, false, NULL, 1, 18, 29, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (66, true, 1, false, NULL, 1, 18, 30, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (67, true, 1, false, NULL, 1, 18, 30, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (124, true, 1, false, NULL, 1, 25, 59, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (125, true, 1, false, NULL, 1, 25, 59, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (126, true, 1, false, NULL, 1, 25, 60, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (127, true, 1, false, NULL, 1, 25, 60, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (120, true, 1, false, NULL, 1, 26, 57, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (121, true, 1, false, NULL, 1, 26, 57, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (122, true, 1, false, NULL, 1, 26, 58, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (123, true, 1, false, NULL, 1, 26, 58, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (116, true, 1, false, NULL, 1, 27, 55, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (117, true, 1, false, NULL, 1, 27, 55, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (118, true, 1, false, NULL, 1, 27, 56, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (119, true, 1, false, NULL, 1, 27, 56, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (112, true, 1, false, NULL, 1, 28, 53, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (113, true, 1, false, NULL, 1, 28, 53, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (114, true, 1, false, NULL, 1, 28, 54, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (115, true, 1, false, NULL, 1, 28, 54, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (108, true, 1, false, NULL, 1, 29, 51, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (109, true, 1, false, NULL, 1, 29, 51, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (110, true, 1, false, NULL, 1, 29, 52, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (111, true, 1, false, NULL, 1, 29, 52, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (104, true, 1, false, NULL, 1, 30, 49, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (105, true, 1, false, NULL, 1, 30, 49, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (106, true, 1, false, NULL, 1, 30, 50, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (107, true, 1, false, NULL, 1, 30, 50, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (100, true, 1, false, NULL, 1, 31, 47, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (101, true, 1, false, NULL, 1, 31, 47, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (102, true, 1, false, NULL, 1, 31, 48, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (103, true, 1, false, NULL, 1, 31, 48, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (96, true, 1, false, NULL, 1, 32, 45, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (97, true, 1, false, NULL, 1, 32, 45, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (98, true, 1, false, NULL, 1, 32, 46, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (99, true, 1, false, NULL, 1, 32, 46, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (28, true, 1, false, NULL, 1, 9, 11, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (29, true, 1, false, NULL, 1, 9, 11, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (30, true, 1, false, NULL, 1, 9, 12, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (31, true, 1, false, NULL, 1, 9, 12, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (24, true, 1, false, NULL, 1, 8, 9, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (25, true, 1, false, NULL, 1, 8, 9, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (26, true, 1, false, NULL, 1, 8, 10, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (27, true, 1, false, NULL, 1, 8, 10, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (20, true, 1, false, NULL, 1, 7, 7, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (21, true, 1, false, NULL, 1, 7, 7, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (22, true, 1, false, NULL, 1, 7, 8, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (23, true, 1, false, NULL, 1, 7, 8, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (16, true, 1, false, NULL, 1, 6, 5, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (17, true, 1, false, NULL, 1, 6, 5, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (18, true, 1, false, NULL, 1, 6, 6, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (19, true, 1, false, NULL, 1, 6, 6, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (12, true, 1, false, NULL, 1, 5, 3, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (13, true, 1, false, NULL, 1, 5, 3, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (14, true, 1, false, NULL, 1, 5, 4, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (15, true, 1, false, NULL, 1, 5, 4, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (8, true, 1, false, NULL, 1, 6, 5, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (9, true, 1, false, NULL, 1, 5, 3, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (10, true, 1, false, NULL, 1, 5, 3, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (11, true, 1, false, NULL, 1, 5, 3, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (4, true, 1, false, NULL, 1, 4, 2, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (5, true, 1, false, NULL, 1, 5, 3, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (6, true, 1, false, NULL, 1, 5, 4, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (7, true, 1, false, NULL, 1, 6, 5, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (1, true, 1, false, NULL, 1, 4, 1, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (3, true, 1, false, NULL, 1, 4, 2, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (60, true, 1, false, NULL, 1, 17, 27, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (61, true, 1, false, NULL, 1, 17, 27, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (62, true, 1, false, NULL, 1, 17, 28, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (63, true, 1, false, NULL, 1, 17, 28, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (56, true, 1, false, NULL, 1, 16, 25, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (57, true, 1, false, NULL, 1, 16, 25, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (58, true, 1, false, NULL, 1, 16, 26, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (59, true, 1, false, NULL, 1, 16, 26, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (52, true, 1, false, NULL, 1, 15, 23, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (53, true, 1, false, NULL, 1, 15, 23, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (54, true, 1, false, NULL, 1, 15, 24, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (55, true, 1, false, NULL, 1, 15, 24, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (48, true, 1, false, NULL, 1, 14, 21, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (49, true, 1, false, NULL, 1, 14, 21, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (50, true, 1, false, NULL, 1, 14, 22, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (51, true, 1, false, NULL, 1, 14, 22, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (44, true, 1, false, NULL, 1, 13, 19, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (45, true, 1, false, NULL, 1, 13, 19, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (46, true, 1, false, NULL, 1, 13, 20, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (47, true, 1, false, NULL, 1, 13, 20, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (40, true, 1, false, NULL, 1, 12, 17, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (41, true, 1, false, NULL, 1, 12, 17, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (42, true, 1, false, NULL, 1, 12, 18, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (43, true, 1, false, NULL, 1, 12, 18, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (36, true, 1, false, NULL, 1, 11, 15, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (38, true, 1, false, NULL, 1, 11, 16, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (39, true, 1, false, NULL, 1, 11, 16, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (32, true, 1, false, NULL, 1, 10, 13, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (33, true, 1, false, NULL, 1, 10, 13, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (34, true, 1, false, NULL, 1, 10, 14, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (35, true, 1, false, NULL, 1, 10, 14, 101);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (220, true, 1, false, NULL, 1, 60, 107, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (221, true, 1, false, NULL, 1, 60, 107, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (222, true, 1, false, NULL, 1, 61, 108, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (223, true, 1, false, NULL, 1, 61, 108, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (216, true, 1, false, NULL, 1, 58, 105, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (217, true, 1, false, NULL, 1, 58, 105, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (218, true, 1, false, NULL, 1, 59, 106, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (219, true, 1, false, NULL, 1, 59, 106, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (212, true, 1, false, NULL, 1, 56, 103, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (213, true, 1, false, NULL, 1, 56, 103, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (214, true, 1, false, NULL, 1, 57, 104, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (215, true, 1, false, NULL, 1, 57, 104, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (208, true, 1, false, NULL, 1, 54, 101, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (209, true, 1, false, NULL, 1, 54, 101, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (210, true, 1, false, NULL, 1, 55, 102, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (211, true, 1, false, NULL, 1, 55, 102, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (204, true, 1, false, NULL, 1, 52, 99, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (205, true, 1, false, NULL, 1, 52, 99, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (206, true, 1, false, NULL, 1, 53, 100, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (207, true, 1, false, NULL, 1, 53, 100, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (200, true, 1, false, NULL, 1, 50, 97, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (201, true, 1, false, NULL, 1, 50, 97, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (202, true, 1, false, NULL, 1, 51, 98, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (203, true, 1, false, NULL, 1, 51, 98, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (196, true, 1, false, NULL, 1, 52, 95, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (197, true, 1, false, NULL, 1, 52, 95, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (198, true, 1, false, NULL, 1, 53, 96, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (199, true, 1, false, NULL, 1, 53, 96, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (192, true, 1, false, NULL, 1, 50, 93, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (193, true, 1, false, NULL, 1, 50, 93, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (194, true, 1, false, NULL, 1, 51, 94, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (195, true, 1, false, NULL, 1, 51, 94, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (252, true, 1, false, NULL, 1, 58, 123, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (253, true, 1, false, NULL, 1, 58, 123, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (254, true, 1, false, NULL, 1, 59, 124, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (255, true, 1, false, NULL, 1, 59, 124, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (248, true, 1, false, NULL, 1, 56, 121, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (249, true, 1, false, NULL, 1, 56, 121, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (250, true, 1, false, NULL, 1, 57, 122, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (251, true, 1, false, NULL, 1, 57, 122, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (244, true, 1, false, NULL, 1, 54, 119, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (245, true, 1, false, NULL, 1, 54, 119, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (246, true, 1, false, NULL, 1, 55, 120, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (247, true, 1, false, NULL, 1, 55, 120, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (240, true, 1, false, NULL, 1, 70, 117, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (241, true, 1, false, NULL, 1, 70, 117, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (242, true, 1, false, NULL, 1, 71, 118, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (243, true, 1, false, NULL, 1, 71, 118, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (236, true, 1, false, NULL, 1, 68, 115, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (237, true, 1, false, NULL, 1, 68, 115, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (238, true, 1, false, NULL, 1, 69, 116, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (239, true, 1, false, NULL, 1, 69, 116, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (232, true, 1, false, NULL, 1, 66, 113, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (233, true, 1, false, NULL, 1, 66, 113, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (234, true, 1, false, NULL, 1, 67, 114, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (235, true, 1, false, NULL, 1, 67, 114, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (228, true, 1, false, NULL, 1, 64, 111, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (229, true, 1, false, NULL, 1, 64, 111, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (230, true, 1, false, NULL, 1, 65, 112, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (231, true, 1, false, NULL, 1, 65, 112, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (224, true, 1, false, NULL, 1, 62, 109, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (225, true, 1, false, NULL, 1, 62, 109, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (226, true, 1, false, NULL, 1, 63, 110, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (227, true, 1, false, NULL, 1, 63, 110, 104);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (156, true, 1, false, NULL, 1, 41, 75, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (157, true, 1, false, NULL, 1, 41, 75, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (158, true, 1, false, NULL, 1, 41, 76, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (159, true, 1, false, NULL, 1, 41, 76, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (152, true, 1, false, NULL, 1, 40, 73, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (153, true, 1, false, NULL, 1, 40, 73, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (154, true, 1, false, NULL, 1, 40, 74, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (155, true, 1, false, NULL, 1, 40, 74, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (148, true, 1, false, NULL, 1, 39, 71, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (149, true, 1, false, NULL, 1, 39, 71, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (150, true, 1, false, NULL, 1, 39, 72, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (151, true, 1, false, NULL, 1, 39, 72, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (144, true, 1, false, NULL, 1, 38, 69, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (145, true, 1, false, NULL, 1, 38, 69, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (146, true, 1, false, NULL, 1, 38, 70, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (147, true, 1, false, NULL, 1, 38, 70, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (140, true, 1, false, NULL, 1, 21, 67, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (141, true, 1, false, NULL, 1, 21, 67, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (142, true, 1, false, NULL, 1, 21, 68, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (143, true, 1, false, NULL, 1, 21, 68, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (136, true, 1, false, NULL, 1, 22, 65, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (137, true, 1, false, NULL, 1, 22, 65, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (138, true, 1, false, NULL, 1, 22, 66, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (139, true, 1, false, NULL, 1, 22, 66, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (132, true, 1, false, NULL, 1, 23, 63, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (133, true, 1, false, NULL, 1, 23, 63, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (134, true, 1, false, NULL, 1, 23, 64, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (135, true, 1, false, NULL, 1, 23, 64, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (128, true, 1, false, NULL, 1, 24, 61, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (129, true, 1, false, NULL, 1, 24, 61, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (130, true, 1, false, NULL, 1, 24, 62, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (131, true, 1, false, NULL, 1, 24, 62, 102);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (188, true, 1, false, NULL, 1, 49, 91, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (189, true, 1, false, NULL, 1, 49, 91, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (190, true, 1, false, NULL, 1, 49, 92, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (191, true, 1, false, NULL, 1, 49, 92, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (184, true, 1, false, NULL, 1, 48, 89, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (185, true, 1, false, NULL, 1, 48, 89, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (186, true, 1, false, NULL, 1, 48, 90, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (187, true, 1, false, NULL, 1, 48, 90, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (180, true, 1, false, NULL, 1, 46, 87, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (181, true, 1, false, NULL, 1, 46, 87, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (182, true, 1, false, NULL, 1, 47, 88, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (183, true, 1, false, NULL, 1, 47, 88, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (176, true, 1, false, NULL, 1, 46, 85, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (177, true, 1, false, NULL, 1, 46, 85, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (178, true, 1, false, NULL, 1, 47, 86, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (179, true, 1, false, NULL, 1, 47, 86, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (172, true, 1, false, NULL, 1, 45, 83, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (173, true, 1, false, NULL, 1, 45, 83, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (174, true, 1, false, NULL, 1, 45, 84, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (175, true, 1, false, NULL, 1, 45, 84, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (168, true, 1, false, NULL, 1, 44, 81, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (169, true, 1, false, NULL, 1, 44, 81, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (170, true, 1, false, NULL, 1, 44, 82, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (171, true, 1, false, NULL, 1, 44, 82, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (164, true, 1, false, NULL, 1, 43, 79, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (165, true, 1, false, NULL, 1, 43, 79, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (166, true, 1, false, NULL, 1, 43, 80, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (167, true, 1, false, NULL, 1, 43, 80, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (160, true, 1, false, NULL, 1, 42, 77, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (161, true, 1, false, NULL, 1, 42, 77, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (162, true, 1, false, NULL, 1, 42, 78, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (163, true, 1, false, NULL, 1, 42, 78, 103);
INSERT INTO public.counters (id, is_active, current_value, is_fixed, last_updated, old_value, address_id, debt_id, user_id) VALUES (2, true, 1, false, NULL, 1, 4, 1, 101);


--
-- TOC entry 3013 (class 0 OID 21664)
-- Dependencies: 198
-- Data for Name: databasechangelog; Type: TABLE DATA; Schema: public; Owner: postgres
--

--
-- TOC entry 3012 (class 0 OID 21659)
-- Dependencies: 197
-- Data for Name: databasechangeloglock; Type: TABLE DATA; Schema: public; Owner: postgres
--


--
-- TOC entry 3036 (class 0 OID 21726)
-- Dependencies: 221
-- Data for Name: email_token; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- TOC entry 3041 (class 0 OID 21751)
-- Dependencies: 226
-- Data for Name: prices; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.prices (price_id, active, date, price, utility_id) VALUES (2, true, '2018-09-04', 3.3300000000000001, 2);
INSERT INTO public.prices (price_id, active, date, price, utility_id) VALUES (3, true, '2018-09-04', 5.3600000000000003, 3);


--
-- TOC entry 3039 (class 0 OID 21741)
-- Dependencies: 224
-- Data for Name: new_prices; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.new_prices (new_price_id, activation_date, new_price, current_price_id) VALUES (1, '2018-10-01', 36.149999999999999, 2);
INSERT INTO public.new_prices (new_price_id, activation_date, new_price, current_price_id) VALUES (2, '2018-09-30', 7.25, 3);


--
-- TOC entry 3040 (class 0 OID 21746)
-- Dependencies: 225
-- Data for Name: payments_histories; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.payments_histories (id, checkpath, google_drive_file_id, pay_date, payment_sum, address_id, utility_id) VALUES (1, '/files/checks/user1@gmail.com/ДнепрОблЭнерго2018-09-04 172458.415.pdf', '18nEiUftyOPf65hcWlYbK-FvLLXKJH_UU', '2018-09-04', 6, 11, 2);


--
-- TOC entry 3042 (class 0 OID 21756)
-- Dependencies: 227
-- Data for Name: rating; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.rating (id, rating, user_id) VALUES (2, 3.5, 101);
INSERT INTO public.rating (id, rating, user_id) VALUES (1, 4, 109);


--
-- TOC entry 3043 (class 0 OID 21761)
-- Dependencies: 228
-- Data for Name: rating_list_item; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.rating_list_item (id, rating_value, user_id, rater_user_id) VALUES (2, 3.5, 101, 109);
INSERT INTO public.rating_list_item (id, rating_value, user_id, rater_user_id) VALUES (1, 4, 109, 101);


--
-- TOC entry 3045 (class 0 OID 21771)
-- Dependencies: 230
-- Data for Name: schedule_history; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (1, '', '2018-09-30', 'DONE', '2018-09-04', 4, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (2, '', '2018-09-29', 'DONE', '2018-09-04', 17, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (3, '', '2018-09-28', 'DONE', '2018-09-04', 9, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (4, '', '2018-09-27', 'CANCELED', '2018-09-04', 16, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (5, '', '2018-09-26', 'CANCELED', '2018-09-04', 13, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (6, '', '2018-09-25', 'CANCELED', '2018-09-04', 15, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (7, '', '2018-09-24', 'DONE', '2018-09-04', 20, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (8, '', '2018-09-21', 'CANCELED', '2018-09-04', 19, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (9, '', '2018-09-21', 'CANCELED', '2018-09-04', 18, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (10, '', '2018-09-21', 'CANCELED', '2018-09-04', 12, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (11, '', '2018-09-21', 'CANCELED', '2018-09-04', 14, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (12, 'Overdue visit', '2018-08-27', 'OVERDUE', '2018-08-27', 18, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (22, 'Overdue visit', '2018-08-27', 'OVERDUE', '2018-08-27', 14, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (18, 'Overdue visit', '2018-08-14', 'OVERDUE', '2018-08-14', 9, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (17, 'Overdue visit', '2018-08-14', 'OVERDUE', '2018-08-14', 13, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (16, 'Overdue visit', '2018-08-14', 'OVERDUE', '2018-08-14', 15, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (23, 'Overdue visit', '2018-08-27', 'OVERDUE', '2018-08-27', 19, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (15, 'Overdue visit', '2018-08-14', 'OVERDUE', '2018-08-14', 20, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (14, 'Overdue visit', '2018-08-14', 'OVERDUE', '2018-08-14', 12, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (13, 'Overdue visit', '2018-08-14', 'OVERDUE', '2018-08-14', 16, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (19, 'Overdue visit', '2018-08-27', 'OVERDUE', '2018-08-27', 9, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (20, 'Overdue visit', '2018-08-27', 'OVERDUE', '2018-08-27', 17, 109);
INSERT INTO public.schedule_history (id, comment, event_date, status, submit_date, address_id, user_id) VALUES (21, 'Overdue visit', '2018-08-27', 'OVERDUE', '2018-08-27', 4, 109);


--
-- TOC entry 3046 (class 0 OID 21779)
-- Dependencies: 231
-- Data for Name: schedules; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (7, '2018-09-30', true, 27, 110);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (10, '2018-09-29', true, 33, 110);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (13, '2018-09-28', true, 32, 110);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (15, '2018-09-27', true, 28, 110);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (16, '2018-09-26', true, 34, 110);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (17, '2018-09-30', true, 64, 112);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (18, '2018-09-29', true, 65, 112);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (19, '2018-09-28', true, 67, 112);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (20, '2018-09-30', true, 43, 111);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (21, '2018-09-27', true, 69, 112);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (22, '2018-09-26', true, 58, 112);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (23, '2018-09-29', true, 52, 111);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (24, '2018-09-25', true, 35, 112);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (25, '2018-09-24', true, 63, 112);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (26, '2018-09-23', true, 62, 112);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (27, '2018-09-22', true, 68, 112);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (28, '2018-09-21', true, 66, 112);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (29, '2018-09-28', true, 51, 111);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (30, '2018-09-27', true, 45, 111);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (31, '2018-09-26', true, 48, 111);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (32, '2018-09-20', true, 23, 112);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (33, '2018-09-25', true, 44, 111);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (37, '2018-09-28', true, 17, 109);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (38, '2018-09-27', true, 9, 109);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (39, '2018-09-26', true, 18, 109);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (40, '2018-09-25', true, 19, 109);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (41, '2018-09-24', true, 14, 109);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (43, '2018-09-10', true, 13, 109);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (44, '2018-09-10', true, 15, 109);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (42, '2018-09-10', true, 16, 109);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (1, '2018-10-10', true, 4, 109);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (35, '2018-09-10', true, 20, 109);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (36, '2018-09-10', true, 12, 109);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (45, '2018-09-06', false, 17, 111);
INSERT INTO public.schedules (id, event_date, is_repeat, address_id, user_id) VALUES (46, '2018-09-07', false, 17, 111);


--
-- TOC entry 3048 (class 0 OID 21789)
-- Dependencies: 233
-- Data for Name: unscheduled_addresses; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (1, 4, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (2, 58, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (3, 21, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (4, 41, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (5, 61, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (6, 25, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (7, 69, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (8, 30, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (9, 60, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (10, 46, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (11, 42, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (12, 37, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (13, 31, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (14, 67, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (15, 40, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (16, 71, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (17, 11, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (18, 65, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (19, 35, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (20, 7, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (21, 62, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (22, 52, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (23, 23, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (24, 39, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (25, 38, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (26, 64, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (27, 36, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (28, 6, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (29, 50, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (30, 24, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (31, 51, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (32, 63, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (33, 22, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (34, 56, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (35, 45, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (36, 8, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (37, 49, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (38, 70, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (39, 55, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (40, 10, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (41, 68, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (42, 59, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (43, 29, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (44, 54, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (45, 26, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (46, 53, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (47, 5, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (48, 43, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (49, 66, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (50, 44, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (51, 57, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (52, 48, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (53, 47, 2);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (54, 37, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (55, 34, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (56, 6, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (57, 50, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (58, 47, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (59, 41, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (60, 36, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (61, 39, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (62, 21, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (63, 30, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (64, 38, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (65, 25, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (66, 61, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (67, 16, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (68, 15, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (69, 13, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (70, 60, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (71, 42, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (72, 5, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (73, 20, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (74, 17, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (75, 57, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (76, 55, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (77, 12, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (78, 11, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (79, 31, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (80, 46, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (81, 54, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (82, 27, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (83, 56, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (84, 14, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (85, 7, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (86, 59, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (87, 22, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (88, 28, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (89, 32, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (90, 9, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (91, 24, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (92, 70, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (93, 71, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (94, 33, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (95, 18, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (96, 19, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (97, 53, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (98, 26, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (99, 29, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (100, 49, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (101, 10, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (102, 8, 3);
INSERT INTO public.unscheduled_addresses (id, address_id, utility_id) VALUES (103, 40, 3);


--
-- TOC entry 3049 (class 0 OID 21794)
-- Dependencies: 234
-- Data for Name: user_address; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.user_address (user_id, address_id) VALUES (101, 4);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 5);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 6);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 7);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 8);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 9);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 10);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 11);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 12);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 13);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 14);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 15);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 16);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 17);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 18);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 19);
INSERT INTO public.user_address (user_id, address_id) VALUES (101, 20);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 21);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 22);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 23);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 24);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 25);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 26);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 27);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 28);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 29);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 30);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 31);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 32);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 33);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 34);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 35);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 36);
INSERT INTO public.user_address (user_id, address_id) VALUES (102, 37);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 38);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 39);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 40);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 41);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 42);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 43);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 44);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 45);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 46);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 47);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 48);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 49);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 50);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 51);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 52);
INSERT INTO public.user_address (user_id, address_id) VALUES (103, 53);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 54);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 55);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 56);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 57);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 58);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 59);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 60);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 61);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 62);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 63);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 64);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 65);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 66);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 67);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 68);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 69);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 70);
INSERT INTO public.user_address (user_id, address_id) VALUES (104, 71);
INSERT INTO public.user_address (user_id, address_id) VALUES (109, 15);
INSERT INTO public.user_address (user_id, address_id) VALUES (110, 31);
INSERT INTO public.user_address (user_id, address_id) VALUES (111, 51);
INSERT INTO public.user_address (user_id, address_id) VALUES (112, 63);


--
-- TOC entry 3052 (class 0 OID 21815)
-- Dependencies: 237
-- Data for Name: utilities_counters; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 2);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 4);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 13);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 15);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 17);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 19);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 21);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 23);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 25);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 27);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 29);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 31);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 33);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 35);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 37);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 39);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 41);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 43);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 45);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 47);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 49);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 51);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 53);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 55);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 57);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 59);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 61);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 63);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 65);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 67);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 69);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 71);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 73);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 75);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 77);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 79);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 81);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 83);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 85);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 87);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 89);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 91);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 93);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 95);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 97);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 99);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 101);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 103);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 105);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 107);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 109);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 111);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 113);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 115);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 117);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 119);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 121);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 123);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 125);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 127);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 129);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 131);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 133);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 135);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 137);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 139);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 141);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 143);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 145);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 147);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 149);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 151);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 153);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 155);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 157);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 159);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 161);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 163);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 165);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 167);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 169);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 171);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 173);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 175);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 177);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 179);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 181);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 183);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 185);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 187);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 189);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 191);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 193);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 195);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 197);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 199);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 201);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 203);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 205);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 207);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 209);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 211);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 213);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 215);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 217);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 219);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 221);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 223);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 225);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 227);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 229);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 231);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 233);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 235);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 237);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 239);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 241);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (2, 243);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 245);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 247);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 249);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 251);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 253);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 255);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 257);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 259);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 261);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 263);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 265);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 267);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 269);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 271);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 273);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 275);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 277);
INSERT INTO public.utilities_counters (utility_id, counter_id) VALUES (3, 279);


--
-- TOC entry 3053 (class 0 OID 21820)
-- Dependencies: 238
-- Data for Name: utilities_users; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.utilities_users (utility_id, user_id) VALUES (2, 109);
INSERT INTO public.utilities_users (utility_id, user_id) VALUES (2, 110);
INSERT INTO public.utilities_users (utility_id, user_id) VALUES (3, 111);
INSERT INTO public.utilities_users (utility_id, user_id) VALUES (3, 112);


--
-- TOC entry 3059 (class 0 OID 0)
-- Dependencies: 199
-- Name: address_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.address_item_id_seq', 71, true);


--
-- TOC entry 3060 (class 0 OID 0)
-- Dependencies: 200
-- Name: city_sequence_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.city_sequence_item_id_seq', 67, true);


--
-- TOC entry 3061 (class 0 OID 0)
-- Dependencies: 201
-- Name: counter_sequence_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.counter_sequence_item_id_seq', 279, true);


--
-- TOC entry 3062 (class 0 OID 0)
-- Dependencies: 202
-- Name: debt_sequence_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.debt_sequence_item_id_seq', 136, true);


--
-- TOC entry 3063 (class 0 OID 0)
-- Dependencies: 203
-- Name: flat_sequence_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.flat_sequence_item_id_seq', 71, true);


--
-- TOC entry 3064 (class 0 OID 0)
-- Dependencies: 204
-- Name: hibernate_sequence; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.hibernate_sequence', 1, false);


--
-- TOC entry 3065 (class 0 OID 0)
-- Dependencies: 205
-- Name: house_sequence_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.house_sequence_item_id_seq', 71, true);


--
-- TOC entry 3066 (class 0 OID 0)
-- Dependencies: 206
-- Name: new_price_sequence_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.new_price_sequence_item_id_seq', 2, true);


--
-- TOC entry 3067 (class 0 OID 0)
-- Dependencies: 207
-- Name: payments_history_sequence_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.payments_history_sequence_item_id_seq', 1, true);


--
-- TOC entry 3068 (class 0 OID 0)
-- Dependencies: 208
-- Name: price_sequence_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.price_sequence_item_id_seq', 3, true);


--
-- TOC entry 3069 (class 0 OID 0)
-- Dependencies: 209
-- Name: rating_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.rating_item_id_seq', 2, true);


--
-- TOC entry 3070 (class 0 OID 0)
-- Dependencies: 210
-- Name: rating_list_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.rating_list_item_id_seq', 2, true);


--
-- TOC entry 3071 (class 0 OID 0)
-- Dependencies: 211
-- Name: region_sequence_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.region_sequence_item_id_seq', 2, true);


--
-- TOC entry 3072 (class 0 OID 0)
-- Dependencies: 212
-- Name: schedules_history_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.schedules_history_item_id_seq', 23, true);


--
-- TOC entry 3073 (class 0 OID 0)
-- Dependencies: 213
-- Name: schedules_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.schedules_item_id_seq', 46, true);


--
-- TOC entry 3074 (class 0 OID 0)
-- Dependencies: 214
-- Name: unscheduled_addresses_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.unscheduled_addresses_id_seq', 103, true);


--
-- TOC entry 3075 (class 0 OID 0)
-- Dependencies: 215
-- Name: user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.user_id_seq', 1, false);


--
-- TOC entry 3076 (class 0 OID 0)
-- Dependencies: 216
-- Name: utility_item_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.utility_item_id_seq', 3, true);


-- Completed on 2018-09-04 17:47:55

--
-- PostgreSQL database dump complete
--

