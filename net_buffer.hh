#ifndef _NET_BUFFER_HH_
#define _NET_BUFFER_HH_

#include <cstddef>
#include <memory>
#include <type_traits>

namespace net
{
    inline namespace v1
    {
        template<typename T>
            using allocator = std::allocator<T>;

        /**
         * @brief Buffer interface
         */
        class Buffer
        {
        public:
            virtual void * get_data_void() = 0;
            virtual void const * get_data_void() const = 0;
            virtual std::size_t get_size() const = 0;
            virtual ~Buffer() { }
        };

        /**
         * @brief Represents a data buffer for network communication
         * @tparam T Native type the buffer will hold
         * @tparam align Forced alignment for the buffer. Defaults to alignof(T)
         * @tparam Allocator Memory allocator type
         */
        template<typename T=unsigned char, std::size_t align=alignof(T), typename Allocator=net::allocator<T>>
            class BufferImpl final : public Buffer
            {
            private:
                using storage_type = typename std::aligned_storage<sizeof(T), align>::type;

                Allocator m_allocator;
                storage_type * m_data;
                std::size_t m_num_bytes;
                std::size_t m_num_elements;

            public:
                BufferImpl() :
                    m_data(nullptr),
                    m_num_bytes(0),
                    m_num_elements(0)
                { }

                BufferImpl(std::size_t n, T * data) :
                    BufferImpl()
                {
                    m_num_elements = n;
                    m_data = data;
                    m_num_bytes = sizeof(storage_type) * m_num_elements;
                }

                explicit BufferImpl(std::size_t n, Allocator const & allocator = Allocator()) :
                    BufferImpl()
                {
                    m_allocator = allocator;
                    m_num_elements = n;

                    /* cast is appropriate here since we allocate to the aligned storage type */
                    m_data = reinterpret_cast<storage_type *>(m_allocator.allocate(m_num_elements));
                    m_num_bytes = sizeof(storage_type) * m_num_elements;
                    std::memset(m_data, 0, m_num_bytes);
                }

                BufferImpl(BufferImpl const & other)
                {
                    m_data = reinterpret_cast<storage_type *>(m_allocator.allocate(other.m_num_elements));
                    m_num_bytes = other.m_num_bytes;
                    m_num_elements = other.m_num_elements;
                    std::memcpy(m_data, other.m_data, other.m_num_bytes);
                }

                BufferImpl & operator=(BufferImpl const & other)
                {
                    /* create new memory for other data */
                    auto * tmp = reinterpret_cast<storage_type *>(m_allocator.allocate(other.m_num_elements));
                    /* delete our data since we don't know if we can reuse the region. */
                    m_allocator.deallocate(reinterpret_cast<T *>(m_data), m_num_elements);

                    m_data = tmp;
                    m_num_bytes = other.num_bytes;
                    m_num_elements = other.num_elements;

                    std::memset(m_data, 0, m_num_bytes);

                    return *this;
                }

                BufferImpl(BufferImpl && other) :
                    m_allocator(other.m_allocator),
                    m_data(other.m_data),
                    m_num_bytes(other.m_num_bytes),
                    m_num_elements(other.m_num_elements)
                {
                    /* This will make it so other doesnt deallocate m_data */
                    other.m_data = nullptr;
                }

                BufferImpl & operator=(BufferImpl && other)
                {
                    m_data = other.m_data;
                    m_num_bytes = other.m_num_bytes;
                    m_num_elements = other.m_num_elements;

                    /* This will make it so other doesnt deallocate m_data */
                    other.m_data = nullptr;

                    return *this;
                }

                ~BufferImpl()
                {
                    m_allocator.deallocate(reinterpret_cast<T *>(m_data), m_num_elements);
                    m_data = nullptr;
                }

                void * get_data_void() {
                    return reinterpret_cast<void *>(m_data);
                }

                void const * get_data_void() const {
                    return reinterpret_cast<void *>(m_data);
                }

                storage_type const * get_data() const {
                    return m_data;
                }

                std::size_t get_size() const {
                    return m_num_bytes;
                }
            };


        /**
         * @brief Helper to create a BufferImpl
         * @tparam T See BufferImpl
         * @tparam align See BufferImpl
         * @tparam Allocator See BufferImpl
         * @param n Number of bytes to allocate
         * @param allocator Which allocator to use
         * @return unique_ptr containing BufferImpl
         */
        template<typename T=unsigned char, std::size_t align=alignof(T), typename Allocator=net::allocator<T>>
            std::unique_ptr<BufferImpl<T, align, Allocator>> make_buffer(std::size_t n, Allocator const & allocator = Allocator())
            {
                return std::make_unique<BufferImpl<T,align,Allocator>>(n, allocator);
            }

    } /* end namespace v1 */
} /* end namespace net */

#endif /* guard */
