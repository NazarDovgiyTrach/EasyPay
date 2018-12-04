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

INSERT INTO public.street (id, name, city_id) VALUES (1, 'проспект Незалежності', 1);
INSERT INTO public.street (id, name, city_id) VALUES (2, 'вулиця Ватутіна', 1);
INSERT INTO public.street (id, name, city_id) VALUES (3, 'вулиця Винниченка', 1);
INSERT INTO public.street (id, name, city_id) VALUES (4, 'вулиця Поштова', 1);
INSERT INTO public.street (id, name, city_id) VALUES (5, 'вулиця Гагаріна', 1);
INSERT INTO public.street (id, name, city_id) VALUES (6, 'вулиця Толстого', 1);
INSERT INTO public.street (id, name, city_id) VALUES (7, 'вулиця Горького', 1);
INSERT INTO public.street (id, name, city_id) VALUES (8, 'вулиця Сковороди', 1);


--
-- TOC entry 3038 (class 0 OID 21736)
-- Dependencies: 223
-- Data for Name: house; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.house (id, number, street_id) VALUES (1, '131', 1);
INSERT INTO public.house (id, number, street_id) VALUES (2, '18', 2);
INSERT INTO public.house (id, number, street_id) VALUES (3, '3', 3);
INSERT INTO public.house (id, number, street_id) VALUES (4, '1', 4);
INSERT INTO public.house (id, number, street_id) VALUES (5, '4', 5);
INSERT INTO public.house (id, number, street_id) VALUES (6, '2', 6);
INSERT INTO public.house (id, number, street_id) VALUES (7, '12', 7);
INSERT INTO public.house (id, number, street_id) VALUES (8, '43', 8);


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
INSERT INTO public.flat (id, number, house_id) VALUES (9, '5', 7);
INSERT INTO public.flat (id, number, house_id) VALUES (10, '15', 8);


--
-- TOC entry 3032 (class 0 OID 21706)
-- Dependencies: 217
-- Data for Name: addresses; Type: TABLE DATA; Schema: public; Owner: postgres
--

INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (1, true, 48.2690871, 25.924404099999947, 1, 1, 1, 1, 1);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (2, true, 48.025148000000002, 33.469425099999967, 1, 2, 2, 1, 2);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (3, true, 48.2708972, 25.953113400000007, 1, 3, 3, 1, 3);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (4, true, 48.293169499999998, 25.934576099999958, 1, 4, 4, 1, 4);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (5, true, 48.297532199999999, 25.936605999999983, 1, 5, 5, 1, 5);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (6, true, 48.295348099999998, 25.934265600000003, 1, 6, 6, 1, 6);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (7, true, 48.295746200000004, 25.93277850000004, 1, 7, 7, 1, 7);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (8, true, 48.292247599999989, 25.928941000000009, 1, 8, 8, 1, 8);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (9, true, 48.292825800000003, 25.934579600000006, 1, 9, 7, 1, 7);
INSERT INTO public.addresses (id, is_active, lat, lng, city_id, flat_id, house_id, region_id, street_id) VALUES (10, false, 48.2921671, 25.930448399999932, 1, 10, 8, 1, 8);
